/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.ASSERTION;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.CLIENT_SECRET;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_JWT_BEARER;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_PASSWORD;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_REFRESH_TOKEN;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.PASSWORD;

import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.NoOpSecurityCache;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.cache.caffeine.CaffeineSecurityCache;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base implementation of {@link OAuth2TokenService} with a pluggable cache.
 *
 * <p>Since 4.1.0 the response cache is expressed against the {@link SecurityCache} SPI so that
 * customers can plug in a distributed cache (e.g. Redis) rather than being locked into the
 * in-memory Caffeine implementation. The default remains a Caffeine cache configured by the
 * supplied {@link TokenCacheConfiguration}. Cached values are serialized to JSON so they can travel
 * across processes.
 *
 * <p>Concurrent cache-miss requests for the same cache key are collapsed via a single-flight
 * {@link CompletableFuture} map: only the first requester issues the outbound HTTP call and the
 * rest wait on the same future. This prevents thundering-herd fan-out to the identity service after
 * a rolling deploy or a cache eviction.
 */
@java.lang.SuppressWarnings("squid:S1192")
public abstract class AbstractOAuth2TokenService implements OAuth2TokenService, Cacheable {

  private static final Logger LOGGER = LoggerFactory.getLogger(AbstractOAuth2TokenService.class);

  private final SecurityCache<String, String> responseCache;
  private final TokenCacheConfiguration tokenCacheConfiguration;

  private final ConcurrentHashMap<String, CompletableFuture<OAuth2TokenResponse>> inFlight =
      new ConcurrentHashMap<>();

  public AbstractOAuth2TokenService() {
    this(TokenCacheConfiguration.defaultConfiguration(), Ticker.systemTicker(), false);
  }

  /**
   * @param tokenCacheConfiguration the cache configuration used to configure the cache.
   */
  public AbstractOAuth2TokenService(final TokenCacheConfiguration tokenCacheConfiguration) {
    this(tokenCacheConfiguration, Ticker.systemTicker(), false);
  }

  /**
   * Constructor accepting a custom {@link SecurityCache} implementation, for example a distributed
   * cache adapter. When the supplied cache is {@code null} the default Caffeine-backed cache is
   * used.
   *
   * @param tokenCacheConfiguration cache configuration; controls whether caching is disabled
   *     entirely and drives the size/duration of the default Caffeine cache.
   * @param securityCache the cache to use, or {@code null} for the default.
   * @since 4.1.0
   */
  public AbstractOAuth2TokenService(
      @Nonnull final TokenCacheConfiguration tokenCacheConfiguration,
      @Nullable final SecurityCache<String, String> securityCache) {
    Assertions.assertNotNull(tokenCacheConfiguration, "cacheConfiguration is required");
    this.tokenCacheConfiguration = tokenCacheConfiguration;
    this.responseCache =
        selectCache(tokenCacheConfiguration, securityCache, Ticker.systemTicker(), false);
    logCacheState();
  }

  /**
   * Testing constructor. The {@code cacheTicker} and {@code sameThreadCache} parameters only take
   * effect for the default Caffeine cache; when a custom {@link SecurityCache} is passed they are
   * ignored.
   */
  AbstractOAuth2TokenService(
      final TokenCacheConfiguration tokenCacheConfiguration,
      final Ticker cacheTicker,
      final boolean sameThreadCache) {
    Assertions.assertNotNull(tokenCacheConfiguration, "cacheConfiguration is required");
    this.tokenCacheConfiguration = tokenCacheConfiguration;
    this.responseCache = selectCache(tokenCacheConfiguration, null, cacheTicker, sameThreadCache);
    logCacheState();
  }

  private void logCacheState() {
    if (isCacheDisabled()) {
      LOGGER.debug("Configured token service with cache disabled");
    } else {
      LOGGER.debug(
          "Configured token service with {} using cache impl {}",
          tokenCacheConfiguration,
          responseCache.getClass().getSimpleName());
    }
  }

  private static SecurityCache<String, String> selectCache(
      final TokenCacheConfiguration cfg,
      @Nullable final SecurityCache<String, String> supplied,
      final Ticker ticker,
      final boolean sameThread) {
    if (cfg.isCacheDisabled()) {
      return new NoOpSecurityCache<>();
    }
    if (supplied != null) {
      return supplied;
    }
    // Caffeine adapter honors the size and expire-after-write from the configuration.
    // We keep the same-thread executor knob for tests via a small dedicated builder.
    return CaffeineTokenCacheFactory.build(cfg, ticker, sameThread);
  }

  @Override
  public void clearCache() {
    try {
      responseCache.clear();
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.clear threw: {}", e.getMessage());
    }
  }

  @Override
  @Nonnull
  public TokenCacheConfiguration getCacheConfiguration() {
    return tokenCacheConfiguration;
  }

  @Override
  public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(
      @Nonnull final URI tokenEndpointUri,
      @Nonnull final ClientIdentity clientIdentity,
      @Nullable final String zoneId,
      @Nullable final String subdomain,
      @Nullable final Map<String, String> optionalParameters,
      final boolean disableCacheForRequest)
      throws OAuth2ServiceException {
    assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
    assertNotNull(clientIdentity, "clientIdentity is required");

    Map<String, String> parameters =
        new RequestParameterBuilder()
            .withGrantType(GRANT_TYPE_CLIENT_CREDENTIALS)
            .withClientIdentity(clientIdentity)
            .withOptionalParameters(optionalParameters)
            .buildAsMap();

    HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();
    if (zoneId != null) {
      headers.withHeader(HttpHeaders.X_ZID, zoneId);
    }

    return getOAuth2TokenResponse(
        tokenEndpointUri, headers, parameters, subdomain, disableCacheForRequest);
  }

  @Override
  public OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(
      @Nonnull final URI tokenEndpointUri,
      @Nonnull final ClientIdentity clientIdentity,
      @Nonnull final String refreshToken,
      final String subdomain,
      final boolean disableCacheForRequest)
      throws OAuth2ServiceException {
    assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
    assertNotNull(clientIdentity, "clientIdentity is required");
    assertNotNull(refreshToken, "refreshToken is required");

    Map<String, String> parameters =
        new RequestParameterBuilder()
            .withGrantType(GRANT_TYPE_REFRESH_TOKEN)
            .withRefreshToken(refreshToken)
            .withClientIdentity(clientIdentity)
            .buildAsMap();

    HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

    return getOAuth2TokenResponse(
        tokenEndpointUri, headers, parameters, subdomain, disableCacheForRequest);
  }

  @Override
  public OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(
      @Nonnull final URI tokenEndpoint,
      @Nonnull final ClientIdentity clientIdentity,
      @Nonnull final String username,
      @Nonnull final String password,
      @Nullable final String subdomain,
      @Nullable final Map<String, String> optionalParameters,
      final boolean disableCacheForRequest)
      throws OAuth2ServiceException {
    assertNotNull(tokenEndpoint, "tokenEndpoint is required");
    assertNotNull(clientIdentity, "clientIdentity is required");
    assertNotNull(username, "username is required");
    assertNotNull(password, "password is required");

    Map<String, String> parameters =
        new RequestParameterBuilder()
            .withGrantType(GRANT_TYPE_PASSWORD)
            .withUsername(username)
            .withPassword(password)
            .withClientIdentity(clientIdentity)
            .withOptionalParameters(optionalParameters)
            .buildAsMap();

    HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

    return getOAuth2TokenResponse(
        tokenEndpoint, headers, parameters, subdomain, disableCacheForRequest);
  }

  @Override
  public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(
      final URI tokenEndpoint,
      final ClientIdentity clientIdentity,
      final String token,
      @Nullable final String subdomain,
      @Nullable final Map<String, String> optionalParameters,
      final boolean disableCacheForRequest)
      throws OAuth2ServiceException {
    assertNotNull(tokenEndpoint, "tokenEndpoint is required");
    assertNotNull(clientIdentity, "clientIdentity is required");
    assertNotNull(token, "token is required");

    Map<String, String> parameters =
        new RequestParameterBuilder()
            .withGrantType(GRANT_TYPE_JWT_BEARER)
            .withClientIdentity(clientIdentity)
            .withToken(token)
            .withOptionalParameters(optionalParameters)
            .buildAsMap();

    HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

    return getOAuth2TokenResponse(
        tokenEndpoint, headers, parameters, subdomain, disableCacheForRequest);
  }

  @Override
  public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(
      final URI tokenEndpoint,
      final ClientIdentity clientIdentity,
      @Nonnull final String token,
      @Nullable final Map<String, String> optionalParameters,
      final boolean disableCacheForRequest,
      @Nonnull final String zoneId)
      throws OAuth2ServiceException {
    assertNotNull(tokenEndpoint, "tokenEndpoint is required");
    assertNotNull(clientIdentity, "clientIdentity is required");
    assertNotNull(token, "token is required");
    assertNotNull(zoneId, "ZoneId is required to create X-zid header");

    Map<String, String> parameters =
        new RequestParameterBuilder()
            .withGrantType(GRANT_TYPE_JWT_BEARER)
            .withClientIdentity(clientIdentity)
            .withToken(token)
            .withOptionalParameters(optionalParameters)
            .buildAsMap();

    HttpHeaders headers =
        HttpHeadersFactory.createWithoutAuthorizationHeader().withHeader(HttpHeaders.X_ZID, zoneId);

    if (isCacheDisabled() || disableCacheForRequest) {
      return requestAccessToken(tokenEndpoint, headers, parameters);
    }
    return getOrRequestAccessToken(tokenEndpoint, headers, parameters);
  }

  /**
   * Implements the HTTP client specific logic to perform an HTTP request and handle the response.
   */
  protected abstract OAuth2TokenResponse requestAccessToken(
      URI tokenEndpointUri, HttpHeaders headers, Map<String, String> parameters)
      throws OAuth2ServiceException;

  private OAuth2TokenResponse getOAuth2TokenResponse(
      @Nonnull final URI tokenEndpointUri,
      final HttpHeaders headers,
      final Map<String, String> additionalParameters,
      @Nullable final String subdomain,
      final boolean disableCacheForRequest)
      throws OAuth2ServiceException {
    URI tokenEndpointUriWithSubdomainReplaced =
        UriUtil.replaceSubdomain(tokenEndpointUri, subdomain);
    if (isCacheDisabled() || disableCacheForRequest) {
      return requestAccessToken(tokenEndpointUriWithSubdomainReplaced, headers, additionalParameters);
    }
    return getOrRequestAccessToken(
        tokenEndpointUriWithSubdomainReplaced, headers, additionalParameters);
  }

  private OAuth2TokenResponse getOrRequestAccessToken(
      final URI tokenEndpoint, final HttpHeaders headers, final Map<String, String> parameters)
      throws OAuth2ServiceException {
    LOGGER.debug(
        "Token was requested for endpoint uri={} with headers={} and parameters={}",
        tokenEndpoint,
        headers,
        parameters.entrySet().stream()
            .map(
                e -> {
                  if (e.getKey().contains(PASSWORD)
                      || e.getKey().contains(CLIENT_SECRET)
                      || e.getKey().contains(ASSERTION)) {
                    return new AbstractMap.SimpleImmutableEntry<>(e.getKey(), "****");
                  }
                  return e;
                })
            .collect(Collectors.toList()));

    final String fingerprint = fingerprint(tokenEndpoint, headers, parameters);
    final String cacheKey = CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, fingerprint);

    Optional<String> cached = safeGet(cacheKey);
    if (cached.isPresent()) {
      OAuth2TokenResponse fromCache = deserialize(cached.get());
      if (fromCache != null && !isSoonExpired(fromCache)) {
        LOGGER.debug("The token was found in cache");
        logDebug(fromCache);
        return fromCache;
      }
      LOGGER.debug("Cached token needs to be refreshed, requesting a new one");
    } else {
      LOGGER.debug("Token not found in cache, requesting a new one");
    }

    OAuth2TokenResponse response =
        singleFlight(cacheKey, () -> requestAccessToken(tokenEndpoint, headers, parameters));
    // Store the freshly-fetched value; if it lives past its useful window the next lookup will
    // detect the near-expiry via isSoonExpired and refresh again.
    safeSet(cacheKey, serialize(response), tokenCacheConfiguration.getCacheDuration());
    logDebug(response);
    return response;
  }

  private Optional<String> safeGet(final String cacheKey) {
    try {
      return responseCache.get(cacheKey);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.get threw — treating as cache miss: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private void safeSet(final String cacheKey, final String value, final Duration ttl) {
    if (value == null) {
      return;
    }
    try {
      responseCache.set(cacheKey, value, ttl);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.set threw — value not cached: {}", e.getMessage());
    }
  }

  private OAuth2TokenResponse singleFlight(
      final String cacheKey, final CheckedSupplier supplier) throws OAuth2ServiceException {
    // Atomically get-or-create the CF the fetch will complete into.
    CompletableFuture<OAuth2TokenResponse> ours = new CompletableFuture<>();
    CompletableFuture<OAuth2TokenResponse> existing = inFlight.putIfAbsent(cacheKey, ours);
    if (existing != null) {
      // Another thread is fetching. Await its result.
      try {
        return existing.get();
      } catch (InterruptedException ie) {
        Thread.currentThread().interrupt();
        throw OAuth2ServiceException.builder("Interrupted while waiting for in-flight token fetch")
            .withUri(URI.create("about:blank"))
            .build();
      } catch (ExecutionException ee) {
        Throwable cause = ee.getCause();
        if (cause instanceof OAuth2ServiceException oe) {
          throw oe;
        }
        if (cause instanceof RuntimeException re) {
          throw re;
        }
        throw new IllegalStateException(cause);
      }
    }
    // We are the fetcher.
    try {
      OAuth2TokenResponse fetched = supplier.get();
      ours.complete(fetched);
      return fetched;
    } catch (OAuth2ServiceException | RuntimeException e) {
      ours.completeExceptionally(e);
      throw e;
    } finally {
      inFlight.remove(cacheKey, ours);
    }
  }

  @FunctionalInterface
  private interface CheckedSupplier {
    OAuth2TokenResponse get() throws OAuth2ServiceException;
  }

  private boolean isSoonExpired(final OAuth2TokenResponse response) {
    Duration delta = getCacheConfiguration().getTokenExpirationDelta();
    Instant expiration = response.getExpiredAt().minus(delta);
    return expiration.isBefore(Instant.now(getClock()));
  }

  private void logDebug(final OAuth2TokenResponse response) {
    if (!LOGGER.isDebugEnabled() || response == null) {
      return;
    }
    try {
      DecodedJwt decodedJwt = response.getDecodedAccessToken();
      LOGGER.debug("Access token: {}", decodedJwt);
    } catch (final IllegalArgumentException e) {
      LOGGER.debug("Access token can not be logged. {}", e.getMessage());
    }
  }

  /**
   * By default {@link Clock#systemUTC()} is used to determine if a cached token has reached its
   * expiration (exp) point in time. This method can be overridden for testing purposes.
   */
  protected Clock getClock() {
    return Clock.systemUTC();
  }

  private boolean isCacheDisabled() {
    return getCacheConfiguration().isCacheDisabled();
  }

  @Override
  public Object getCacheStatistics() {
    if (!getCacheConfiguration().isCacheStatisticsEnabled()) {
      return null;
    }
    if (responseCache instanceof CaffeineSecurityCache csc) {
      return csc.unwrap().stats();
    }
    return null;
  }

  private static String fingerprint(
      final URI tokenEndpoint, final HttpHeaders headers, final Map<String, String> parameters) {
    // Sort headers and parameters so that map-iteration order does not influence the key.
    Map<String, String> sortedHeaders = new TreeMap<>();
    headers.getHeaders().forEach(h -> sortedHeaders.put(h.getName(), h.getValue()));
    Map<String, String> sortedParams = new TreeMap<>(parameters);
    return "uri=" + tokenEndpoint + "|hdr=" + sortedHeaders + "|prm=" + sortedParams;
  }

  private static String serialize(final OAuth2TokenResponse response) {
    if (response == null) {
      return null;
    }
    JSONObject json = new JSONObject();
    json.put("access_token", response.getAccessToken() == null ? JSONObject.NULL : response.getAccessToken());
    json.put("refresh_token", response.getRefreshToken() == null ? JSONObject.NULL : response.getRefreshToken());
    json.put("token_type", response.getTokenType() == null ? JSONObject.NULL : response.getTokenType());
    json.put("expired_time_millis", response.getExpiredTimeMillis());
    return json.toString();
  }

  private static OAuth2TokenResponse deserialize(final String rawJson) {
    if (rawJson == null || rawJson.isEmpty()) {
      return null;
    }
    try {
      JSONObject json = new JSONObject(rawJson);
      String accessToken = json.isNull("access_token") ? null : json.optString("access_token");
      String refreshToken = json.isNull("refresh_token") ? null : json.optString("refresh_token");
      String tokenType = json.isNull("token_type") ? null : json.optString("token_type");
      long expiredTimeMillis = json.getLong("expired_time_millis");
      return new OAuth2TokenResponse(accessToken, refreshToken, tokenType, expiredTimeMillis);
    } catch (final RuntimeException e) {
      LOGGER.warn("Failed to deserialize cached token response — treating as cache miss: {}", e.getMessage());
      return null;
    }
  }
}
