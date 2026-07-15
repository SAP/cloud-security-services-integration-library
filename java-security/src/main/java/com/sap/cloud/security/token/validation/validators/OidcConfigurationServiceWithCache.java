/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.NoOpSecurityCache;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.cache.caffeine.CaffeineSecurityCache;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.client.DefaultOidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.time.Duration;
import java.util.Optional;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decorates {@link OidcConfigurationService} with a {@link SecurityCache}-backed cache, which gets
 * looked up before the identity service is requested via HTTP.
 *
 * <p>Since 4.1.0 the cache is expressed against the {@link SecurityCache} SPI so that a distributed
 * cache (Redis, Hazelcast, ...) can be plugged in via
 * {@link JwtValidatorBuilder#withSecurityCache(SecurityCache)}. When no external cache is supplied
 * a size- and duration-bounded Caffeine cache is used.
 */
public class OidcConfigurationServiceWithCache implements Cacheable {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(OidcConfigurationServiceWithCache.class);
  private static final long DEFAULT_CACHE_VALIDITY_IN_SECONDS = 600;
  private static final long MAX_CACHE_VALIDITY_IN_SECONDS = 900;
  private static final long MIN_CACHE_VALIDITY_IN_SECONDS = 600;
  private static final int MIN_CACHE_SIZE = 1000;

  private OidcConfigurationService oidcConfigurationService; // access via getter
  private SecurityCache<String, String> cache;
  private long cacheValidityInSeconds = DEFAULT_CACHE_VALIDITY_IN_SECONDS;
  private long cacheSize = 1000;
  private boolean cacheStatisticsEnabled = false;

  private OidcConfigurationServiceWithCache() {
    // use getInstance factory method
  }

  /** Creates a new instance. */
  public static OidcConfigurationServiceWithCache getInstance() {
    return new OidcConfigurationServiceWithCache();
  }

  /**
   * Overwrites the service to be used to request the OIDC configuration.
   *
   * @param oidcConfigurationService the OidcConfigurationService that will be used to request the
   *     oidc configuration.
   * @return this
   */
  public OidcConfigurationServiceWithCache withOidcConfigurationService(
      final OidcConfigurationService oidcConfigurationService) {
    this.oidcConfigurationService = oidcConfigurationService;
    return this;
  }

  /**
   * Caches the OIDC configuration. Overwrite the cache time (default: 600 seconds).
   *
   * @param timeInSeconds time to cache the OIDC discovery response, between 600 and 900 seconds.
   * @return this
   */
  public OidcConfigurationServiceWithCache withCacheTime(final int timeInSeconds) {
    if (timeInSeconds < MIN_CACHE_VALIDITY_IN_SECONDS
        || timeInSeconds > MAX_CACHE_VALIDITY_IN_SECONDS) {
      throw new IllegalArgumentException("The cache validity must be between 600 and 900 seconds.");
    }
    this.cacheValidityInSeconds = timeInSeconds;
    this.cache = null; // force rebuild
    return this;
  }

  /**
   * Overrides the cache size (default: 1000, must be greater than 1000).
   *
   * @param size number of cached OIDC configurations.
   * @return this
   */
  public OidcConfigurationServiceWithCache withCacheSize(final int size) {
    if (size <= MIN_CACHE_SIZE) {
      throw new IllegalArgumentException("The cache size must be 1000 or more");
    }
    this.cacheSize = size;
    this.cache = null;
    return this;
  }

  /**
   * Replaces the default in-memory cache with a caller-supplied {@link SecurityCache}
   * implementation. Passing {@code null} restores the default.
   *
   * @param securityCache the cache to use, or {@code null}
   * @return this
   * @since 4.1.0
   */
  public OidcConfigurationServiceWithCache withSecurityCache(
      @Nullable final SecurityCache<String, String> securityCache) {
    this.cache = securityCache;
    return this;
  }

  /**
   * Returns the cached endpoints for the given discovery URI, or fetches them if not cached.
   *
   * @param discoveryEndpointUri the discovery endpoint URI (issuer specific).
   * @return an endpoints provider, or {@code null} if the discovery response was empty / missing.
   * @throws OAuth2ServiceException if the call to the discovery endpoint of the identity service
   *     failed.
   */
  @Nullable
  public OAuth2ServiceEndpointsProvider getOrRetrieveEndpoints(final URI discoveryEndpointUri)
      throws OAuth2ServiceException {
    assertNotNull(discoveryEndpointUri, "discoveryEndpointUri must not be null.");
    final String cacheKey = buildCacheKey(discoveryEndpointUri);

    Optional<String> cached = safeGet(cacheKey);
    if (cached.isPresent()) {
      OAuth2ServiceEndpointsProvider provider = SerializedEndpoints.fromJson(cached.get());
      if (provider != null) {
        return provider;
      }
      LOGGER.debug("Cached OIDC entry for {} was malformed — refreshing", discoveryEndpointUri);
    }

    OAuth2ServiceEndpointsProvider endpointsProvider =
        getOidcConfigurationService().retrieveEndpoints(discoveryEndpointUri);
    if (endpointsProvider == null) {
      return null;
    }
    safeSet(
        cacheKey,
        SerializedEndpoints.toJson(endpointsProvider),
        Duration.ofSeconds(cacheValidityInSeconds));
    return endpointsProvider;
  }

  private static String buildCacheKey(final URI discoveryEndpointUri) {
    return CacheKeys.build(CacheKeys.NAMESPACE_OIDC, discoveryEndpointUri.toString());
  }

  private Optional<String> safeGet(final String cacheKey) {
    try {
      return getCache().get(cacheKey);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.get failed for OIDC entry: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private void safeSet(final String cacheKey, final String value, final Duration ttl) {
    if (value == null) {
      return;
    }
    try {
      getCache().set(cacheKey, value, ttl);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.set failed for OIDC entry: {}", e.getMessage());
    }
  }

  private SecurityCache<String, String> getCache() {
    SecurityCache<String, String> local = cache;
    if (local == null) {
      local =
          new CaffeineSecurityCache((int) cacheSize, Duration.ofSeconds(cacheValidityInSeconds));
      cache = local;
    }
    return local;
  }

  private OidcConfigurationService getOidcConfigurationService() {
    if (oidcConfigurationService == null) {
      this.oidcConfigurationService = new DefaultOidcConfigurationService();
    }
    return oidcConfigurationService;
  }

  @Override
  public void clearCache() {
    if (cache != null) {
      try {
        cache.clear();
      } catch (final RuntimeException e) {
        LOGGER.warn("SecurityCache.clear failed: {}", e.getMessage());
      }
    }
  }

  @Nonnull
  @Override
  public CacheConfiguration getCacheConfiguration() {
    final long size = cacheSize;
    final Duration duration = Duration.ofSeconds(cacheValidityInSeconds);
    final boolean stats = cacheStatisticsEnabled;
    return new CacheConfiguration() {
      @Nonnull
      @Override
      public Duration getCacheDuration() {
        return duration;
      }

      @Override
      public int getCacheSize() {
        return (int) size;
      }

      @Override
      public boolean isCacheStatisticsEnabled() {
        return stats;
      }
    };
  }

  @Override
  @Nullable
  public Object getCacheStatistics() {
    return null;
  }

  /**
   * Compact JSON envelope used for the OIDC entry. Uses only the three URIs the runtime cares
   * about; format is stable and easy to keep in sync between library versions.
   */
  static final class SerializedEndpoints implements OAuth2ServiceEndpointsProvider {
    private static final String TOKEN_ENDPOINT = "token_endpoint";
    private static final String AUTHORIZE_ENDPOINT = "authorization_endpoint";
    private static final String JWKS_URI = "jwks_uri";

    private final URI tokenEndpoint;
    private final URI authorizeEndpoint;
    private final URI jwksUri;

    private SerializedEndpoints(final URI tokenEndpoint, final URI authorize, final URI jwksUri) {
      this.tokenEndpoint = tokenEndpoint;
      this.authorizeEndpoint = authorize;
      this.jwksUri = jwksUri;
    }

    static String toJson(final OAuth2ServiceEndpointsProvider provider) {
      try {
        JSONObject json = new JSONObject();
        putSafely(json, TOKEN_ENDPOINT, provider);
        putSafely(json, AUTHORIZE_ENDPOINT, provider);
        putSafely(json, JWKS_URI, provider);
        return json.toString();
      } catch (final RuntimeException e) {
        LOGGER.warn("Could not serialize OIDC endpoints for caching: {}", e.getMessage());
        return null;
      }
    }

    private static void putSafely(
        final JSONObject json, final String key, final OAuth2ServiceEndpointsProvider provider) {
      try {
        URI value = switch (key) {
          case TOKEN_ENDPOINT -> provider.getTokenEndpoint();
          case AUTHORIZE_ENDPOINT -> provider.getAuthorizeEndpoint();
          case JWKS_URI -> provider.getJwksUri();
          default -> null;
        };
        if (value != null) {
          json.put(key, value.toString());
        }
      } catch (final RuntimeException e) {
        // Not every provider carries every URI (e.g. tests / IAS discovery may return partial
        // responses). Skip missing / undefined endpoints instead of failing serialization.
        LOGGER.debug("OIDC provider does not carry {}: {}", key, e.getMessage());
      }
    }

    @Nullable
    static SerializedEndpoints fromJson(final String rawJson) {
      if (rawJson == null || rawJson.isEmpty()) {
        return null;
      }
      try {
        JSONObject json = new JSONObject(rawJson);
        return new SerializedEndpoints(
            optUri(json, TOKEN_ENDPOINT),
            optUri(json, AUTHORIZE_ENDPOINT),
            optUri(json, JWKS_URI));
      } catch (final RuntimeException e) {
        LOGGER.warn("Could not deserialize cached OIDC endpoints: {}", e.getMessage());
        return null;
      }
    }

    private static URI optUri(final JSONObject json, final String key) {
      String v = json.optString(key, null);
      return v == null ? null : URI.create(v);
    }

    @Override
    public URI getTokenEndpoint() {
      return tokenEndpoint;
    }

    @Override
    public URI getAuthorizeEndpoint() {
      return authorizeEndpoint;
    }

    @Override
    public URI getJwksUri() {
      return jwksUri;
    }
  }

  /** For tests: exposes the SecurityCache in use. Package-private on purpose. */
  SecurityCache<String, String> internalCacheForTests() {
    return getCache();
  }

  /** Testing hook that lets a caller replace the cache with a {@link NoOpSecurityCache}. */
  OidcConfigurationServiceWithCache withDisabledCacheForTests() {
    this.cache = new NoOpSecurityCache<>();
    return this;
  }
}
