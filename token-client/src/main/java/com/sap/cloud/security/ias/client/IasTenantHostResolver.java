/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.cache.caffeine.CaffeineSecurityCache;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Pattern;

import org.json.JSONObject;
import org.json.JSONTokener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves subscriber IAS tenant hosts dynamically by querying the BTP tenant API.
 * <p>
 * When a multi-tenant IAS application needs to fetch tokens for a subscriber tenant, the IAS token
 * endpoint URL changes based on the subscriber's subdomain. This resolver queries
 * {@code /sap/rest/tenantLoginInfo?id={tenantId}} to discover the subscriber's token endpoint and
 * extracts the subdomain from it.
 *
 * <h2>Security</h2>
 *
 * <ul>
 *   <li>The BTP tenant API base URI must use HTTPS; the resolver rejects any other scheme at
 *       construction time.
 *   <li>The tenant ID is format-validated before the request (alphanumeric, {@code _}, {@code -})
 *       and URL-encoded when placed into the query string.
 *   <li>The subdomain extracted from the response must be a valid DNS label (lowercase
 *       alphanumeric and hyphen). The caller then only replaces the first label of the configured
 *       IAS host (see {@code IasDefaultEndpoints#withSubdomain}), pinning the zone, so the client
 *       credentials are never sent to a host outside the configured IAS zone.
 *   <li>Resolved subdomains are cached under the key {@code tenant-hosts:<app_tid>}. The
 *       {@code app_tid} is a tenant identifier, not a credential, so a human-readable key is safe.
 *   <li>Failures are never cached, and response bodies are not logged at warn level.
 * </ul>
 *
 * <h2>Caching</h2>
 *
 * <p>Resolved subdomains are cached via the {@link SecurityCache} SPI in the
 * {@link CacheKeys#NAMESPACE_TENANT_HOSTS tenant-hosts} namespace. Pass a shared cache (e.g. a
 * distributed Redis-backed adapter) to share resolutions across application instances; when no
 * cache is provided, an in-memory {@link CaffeineSecurityCache} is used. The cache behavior is
 * controlled by an {@link IasTenantHostCacheConfiguration}; pass a config with
 * {@code enabled=false} to disable caching entirely.
 *
 * <h2>Error handling</h2>
 *
 * <p>Every failure is wrapped into an {@link IasTenantHostResolutionException} with a typed
 * {@link IasTenantHostResolutionException.ErrorCode} derived from the HTTP status and the
 * response {@code status} field, so callers can decide on a retry strategy (see the exception
 * documentation for the mapping).
 */
public class IasTenantHostResolver {

  private static final Logger LOGGER = LoggerFactory.getLogger(IasTenantHostResolver.class);
  private static final String TENANT_LOGIN_INFO_PATH = "/sap/rest/tenantLoginInfo";

  /** Accepted tenant ID (app_tid / subaccount ID) format. */
  static final Pattern TENANT_ID_PATTERN = Pattern.compile("[A-Za-z0-9_-]{1,128}");

  /** A valid DNS label: lowercase alphanumeric, hyphen allowed but not at the edges. */
  static final Pattern DNS_LABEL_PATTERN = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

  private static final String STATUS_ACTIVE = "ACTIVE";
  private static final String STATUS_INACTIVE = "INACTIVE";
  private static final String STATUS_NOTRUST = "NOTRUST";
  private static final String STATUS_ERROR = "ERROR";

  private final URI btpTenantApiBaseUri;
  private final SecurityHttpClient httpClient;
  private final IasTenantHostCacheConfiguration cacheConfiguration;
  @Nullable private final SecurityCache<String, String> subdomainCache;

  /**
   * Creates a new resolver with the default cache configuration
   * ({@link IasTenantHostCacheConfiguration#defaultConfiguration()}) and an in-memory Caffeine
   * cache.
   *
   * @param btpTenantApiBaseUri base URI of the BTP tenant API, e.g. {@code https://api.authentication.eu10.hana.ondemand.com}
   * @param httpClient HTTP client to use for requests; must be configured with the application's
   *     IAS service credentials
   * @throws IllegalArgumentException if the base URI does not use HTTPS
   */
  public IasTenantHostResolver(@Nonnull URI btpTenantApiBaseUri, @Nonnull SecurityHttpClient httpClient) {
    this(btpTenantApiBaseUri, httpClient, IasTenantHostCacheConfiguration.defaultConfiguration(), null);
  }

  /**
   * Creates a new resolver with an explicit cache configuration and an in-memory Caffeine cache.
   *
   * @param btpTenantApiBaseUri base URI of the BTP tenant API
   * @param httpClient HTTP client to use for requests
   * @param cacheConfiguration cache configuration; pass a disabled config to skip caching
   * @throws IllegalArgumentException if the base URI does not use HTTPS
   */
  public IasTenantHostResolver(
      @Nonnull URI btpTenantApiBaseUri,
      @Nonnull SecurityHttpClient httpClient,
      @Nonnull IasTenantHostCacheConfiguration cacheConfiguration) {
    this(btpTenantApiBaseUri, httpClient, cacheConfiguration, null);
  }

  /**
   * Creates a new resolver with an explicit cache configuration and an explicitly provided
   * {@link SecurityCache}.
   *
   * @param btpTenantApiBaseUri base URI of the BTP tenant API
   * @param httpClient HTTP client to use for requests
   * @param cacheConfiguration cache configuration; pass a disabled config to skip caching
   * @param cache the cache used for resolved subdomains; may be {@code null} for the in-memory
   *     default (honoring {@code maxSize} and {@code ttl} of the configuration)
   * @throws IllegalArgumentException if the base URI does not use HTTPS
   */
  public IasTenantHostResolver(
      @Nonnull URI btpTenantApiBaseUri,
      @Nonnull SecurityHttpClient httpClient,
      @Nonnull IasTenantHostCacheConfiguration cacheConfiguration,
      @Nullable SecurityCache<String, String> cache) {
    if (btpTenantApiBaseUri == null) {
      throw new IllegalArgumentException("BTP tenant API base URI must not be null");
    }
    if (!"https".equalsIgnoreCase(btpTenantApiBaseUri.getScheme())) {
      throw new IllegalArgumentException(
          "BTP tenant API base URI must use HTTPS, got: " + btpTenantApiBaseUri.getScheme());
    }
    if (httpClient == null) {
      throw new IllegalArgumentException("HTTP client must not be null");
    }
    if (cacheConfiguration == null) {
      throw new IllegalArgumentException("Cache configuration must not be null");
    }
    this.btpTenantApiBaseUri = btpTenantApiBaseUri;
    this.httpClient = httpClient;
    this.cacheConfiguration = cacheConfiguration;
    this.subdomainCache =
        !cacheConfiguration.enabled()
            ? null
            : (cache != null
                ? cache
                : new CaffeineSecurityCache((int) cacheConfiguration.maxSize(), cacheConfiguration.ttl()));
  }

  /**
   * Resolves the IAS subdomain for a given tenant ID.
   * <p>
   * Queries the BTP tenant API; if caching is enabled, subsequent calls with the same tenant ID
   * return the cached value until the TTL expires.
   *
   * @param tenantId the subscriber tenant ID (app_tid / subaccount ID)
   * @return the resolved IAS subdomain
   * @throws IasTenantHostResolutionException if the resolution fails; the
   *     {@link IasTenantHostResolutionException#getErrorCode() error code} tells the caller
   *     whether a retry is sensible
   */
  @Nonnull
  public String resolve(@Nonnull String tenantId) throws IasTenantHostResolutionException {
    validateTenantId(tenantId);
    if (subdomainCache == null) {
      return doResolve(tenantId);
    }
    String cacheKey = CacheKeys.build(CacheKeys.NAMESPACE_TENANT_HOSTS, tenantId);
    Optional<String> cached = subdomainCache.get(cacheKey);
    if (cached.isPresent()) {
      LOGGER.debug("Resolved IAS subdomain for tenant '{}' from cache", tenantId);
      return cached.get();
    }
    String resolved = doResolve(tenantId);
    subdomainCache.set(cacheKey, resolved, cacheConfiguration.ttl());
    return resolved;
  }

  private void validateTenantId(@Nonnull String tenantId) throws IasTenantHostResolutionException {
    if (tenantId == null || !TENANT_ID_PATTERN.matcher(tenantId).matches()) {
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.INVALID_REQUEST,
          "Invalid tenant ID format. The tenant ID must be 1-128 characters of [A-Za-z0-9_-].",
          null);
    }
  }

  private String doResolve(String tenantId) throws IasTenantHostResolutionException {
    URI requestUri = buildRequestUri(tenantId);
    LOGGER.debug("Resolving IAS subdomain for tenant '{}' via {}", tenantId, requestUri);

    SecurityHttpRequest request =
        SecurityHttpRequest.newBuilder()
            .method("GET")
            .uri(requestUri)
            .header("Accept", "application/json")
            .build();

    SecurityHttpResponse response;
    try {
      response = httpClient.execute(request);
    } catch (IOException e) {
      LOGGER.warn(
          "BTP tenant API request failed for tenant '{}': {}",
          tenantId,
          e.getClass().getSimpleName());
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.UPSTREAM_UNAVAILABLE,
          "Failed to resolve IAS subdomain for tenant '%s': transport error: %s"
              .formatted(tenantId, e.getClass().getSimpleName()),
          e);
    }

    int statusCode = response.getStatusCode();
    if (statusCode != 200) {
      throw mapHttpError(statusCode, tenantId, response.getBody());
    }
    return parseSuccessResponse(tenantId, response.getBody());
  }

  private URI buildRequestUri(String tenantId) {
    String query = "id=" + URLEncoder.encode(tenantId, StandardCharsets.UTF_8);
    if (cacheConfiguration.localInformationOnly()) {
      query += "&localInformationOnly=true";
    }
    return URI.create(btpTenantApiBaseUri + TENANT_LOGIN_INFO_PATH + "?" + query);
  }

  private IasTenantHostResolutionException mapHttpError(int statusCode, String tenantId, String body) {
    String detail = extractErrorDetails(body);
    String base = "Failed to resolve IAS subdomain for tenant '%s' (HTTP %d)".formatted(tenantId, statusCode);
    return switch (statusCode) {
      case 400 -> new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.INVALID_REQUEST,
          400,
          base + ". The BTP tenant API rejected the request. " + detail,
          null);
      case 401, 403 -> new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.AUTHENTICATION_FAILED,
          statusCode,
          base + ". The IAS service credentials were rejected by the BTP tenant API. " + detail,
          null);
      case 404 -> new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.TENANT_NOT_FOUND,
          404,
          base + ". The tenant is unknown to the BTP tenant API. " + detail,
          null);
      case 424 -> new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.UPSTREAM_UNAVAILABLE,
          424,
          base + ". The IAS registry returned an error or is temporarily unreachable; a retry may succeed. "
              + detail,
          null);
      case 500 -> new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.UPSTREAM_MISCONFIGURED,
          500,
          base + ". The IAS registry is misconfigured or its certificate is invalid. " + detail,
          null);
      default -> statusCode >= 500
          ? new IasTenantHostResolutionException(
              IasTenantHostResolutionException.ErrorCode.UPSTREAM_UNAVAILABLE,
              statusCode,
              base + ". Transient upstream failure; a retry may succeed. " + detail,
              null)
          : new IasTenantHostResolutionException(
              IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR,
              statusCode,
              base + ". Unexpected client error from the BTP tenant API. " + detail,
              null);
    };
  }

  private String parseSuccessResponse(String tenantId, String body) throws IasTenantHostResolutionException {
    JSONObject json;
    try {
      json = new JSONObject(new JSONTokener(body));
    } catch (RuntimeException e) {
      LOGGER.warn("BTP tenant API returned a malformed response for tenant '{}'", tenantId);
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR,
          "Failed to resolve IAS subdomain for tenant '%s': the BTP tenant API response is not valid JSON."
              .formatted(tenantId),
          e);
    }

    String status = json.optString("status", null);
    String errorDetails = json.optString("error_details", null);
    String details = errorDetails != null && !errorDetails.isBlank() ? " Details: " + errorDetails : "";

    if (STATUS_INACTIVE.equals(status)) {
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.TENANT_INACTIVE,
          200,
          "Failed to resolve IAS subdomain for tenant '%s': the tenant is inactive.%s".formatted(tenantId, details),
          null);
    }
    if (STATUS_NOTRUST.equals(status)) {
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.NOT_TRUSTED,
          200,
          "Failed to resolve IAS subdomain for tenant '%s': no trust relationship between the provider and the"
              + " subscriber tenant is established.%s"
              .formatted(tenantId, details),
          null);
    }
    if (!STATUS_ACTIVE.equals(status)) {
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR,
          200,
          "Failed to resolve IAS subdomain for tenant '%s': unexpected or missing status '%s'.%s"
              .formatted(tenantId, status, details),
          null);
    }

    String subdomain = extractSubdomainFromResponse(json);
    if (subdomain == null) {
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR,
          200,
          "Failed to resolve IAS subdomain for tenant '%s': the response did not contain a usable"
              + " token_endpoint.".formatted(tenantId),
          null);
    }
    if (!DNS_LABEL_PATTERN.matcher(subdomain).matches()) {
      LOGGER.warn(
          "BTP tenant API returned an IAS subdomain for tenant '{}' that is not a valid DNS label; "
              + "rejecting it. Review the BTP tenant API response.",
          tenantId);
      throw new IasTenantHostResolutionException(
          IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR,
          200,
          "Failed to resolve IAS subdomain for tenant '%s': the resolved host label is not a valid DNS label."
              .formatted(tenantId),
          null);
    }
    LOGGER.debug("Resolved IAS subdomain for tenant '{}': '{}'", tenantId, subdomain);
    return subdomain;
  }

  /**
   * Extracts and validates the IAS subdomain from a parsed tenantLoginInfo response.
   * <p>
   * The response contains a {@code token_endpoint} field like
   * {@code https://subscriber.accounts.ondemand.com/oauth2/token}. The first host label is the
   * subdomain. The endpoint must be an absolute HTTPS URL with a host; anything else yields
   * {@code null}.
   *
   * @return the subdomain, or {@code null} if the response does not yield a usable HTTPS endpoint
   */
  @Nullable
  static String extractSubdomainFromResponse(JSONObject json) {
    String tokenEndpoint = json.optString("token_endpoint", null);
    if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
      return null;
    }
    URI tokenUri;
    try {
      tokenUri = URI.create(tokenEndpoint);
    } catch (RuntimeException e) {
      return null;
    }
    if (!"https".equalsIgnoreCase(tokenUri.getScheme()) || tokenUri.getHost() == null) {
      return null;
    }
    String host = tokenUri.getHost().toLowerCase();
    int dotIndex = host.indexOf('.');
    if (dotIndex < 0) {
      return host;
    }
    return host.substring(0, dotIndex);
  }

  /**
   * Extracts a short, log-safe error detail from an error response body. The full body is not
   * returned; at most the API's {@code error_details} / {@code message} / {@code messageText}
   * fields are used, truncated to 200 characters.
   */
  static String extractErrorDetails(String body) {
    if (body == null || body.isBlank()) {
      return "";
    }
    try {
      JSONObject json = new JSONObject(new JSONTokener(body));
      String detail =
          json.optString("error_details", null) != null
              ? json.optString("error_details")
              : json.optString("message", json.optString("messageText", ""));
      if (detail.isBlank()) {
        return "";
      }
      return detail.length() > 200 ? detail.substring(0, 200) + "..." : detail;
    } catch (RuntimeException e) {
      return "";
    }
  }

  /**
   * @return the cache configuration this resolver was constructed with
   */
  @Nonnull
  public IasTenantHostCacheConfiguration getCacheConfiguration() {
    return cacheConfiguration;
  }

  /**
   * Clears the subdomain cache. No-op if caching is disabled.
   */
  public void clearCache() {
    if (subdomainCache != null) {
      subdomainCache.clear();
    }
  }
}
