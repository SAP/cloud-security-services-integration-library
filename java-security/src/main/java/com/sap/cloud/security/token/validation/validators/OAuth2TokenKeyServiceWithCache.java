/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.NoOpSecurityCache;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.cache.caffeine.CaffeineSecurityCache;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.util.LogSanitizer;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decorates {@link OAuth2TokenKeyService} with a {@link SecurityCache}-backed cache, which gets
 * looked up before the identity service is requested via HTTP.
 *
 * <p>Since 4.1.0 the cache is expressed against the {@link SecurityCache} SPI. The cached value is
 * the raw JWKS JSON as returned by the identity service; the {@link JsonWebKeySet} is rebuilt on
 * every hit. That makes cached entries safe to share across processes at the cost of a small,
 * predictable per-hit CPU overhead.
 */
class OAuth2TokenKeyServiceWithCache implements Cacheable {
  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2TokenKeyServiceWithCache.class);

  private OAuth2TokenKeyService tokenKeyService;
  private SecurityCache<String, String> cache;
  private CacheConfiguration cacheConfiguration = TokenKeyCacheConfiguration.defaultConfiguration();
  private Ticker ticker = Ticker.systemTicker();

  private OAuth2TokenKeyServiceWithCache() {
    // use getInstance factory method
  }

  /** Creates a new instance. */
  public static OAuth2TokenKeyServiceWithCache getInstance() {
    return new OAuth2TokenKeyServiceWithCache();
  }

  /**
   * Creates a new instance and sets the cache ticker. This is used for testing.
   *
   * @param cacheTicker ticker used by the default Caffeine-backed cache for expiration.
   */
  static OAuth2TokenKeyServiceWithCache getInstance(final Ticker cacheTicker) {
    OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
    instance.ticker = cacheTicker;
    return instance;
  }

  /**
   * Configures the token key cache. Use
   * {@link TokenKeyCacheConfiguration#getInstance(Duration, int, boolean)} to pass a custom
   * configuration.
   *
   * <p>Note that the cache size must be 1000 or more and the cache duration must be at least 600
   * seconds!
   */
  public OAuth2TokenKeyServiceWithCache withCacheConfiguration(
      final CacheConfiguration cacheConfiguration) {
    this.cacheConfiguration = getCheckedConfiguration(cacheConfiguration);
    // Force cache rebuild with the new configuration next time it's needed.
    this.cache = null;
    LOGGER.debug(
        "Configured token key cache with cacheDuration={} seconds, cacheSize={} and statisticsRecording={}",
        getCacheConfiguration().getCacheDuration().getSeconds(),
        getCacheConfiguration().getCacheSize(),
        getCacheConfiguration().isCacheStatisticsEnabled());
    return this;
  }

  /**
   * Overwrites the service to be used to request the JSON Web Keys.
   *
   * @param tokenKeyService the service to request the json web key set.
   * @return this
   */
  public OAuth2TokenKeyServiceWithCache withTokenKeyService(
      final OAuth2TokenKeyService tokenKeyService) {
    this.tokenKeyService = tokenKeyService;
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
  public OAuth2TokenKeyServiceWithCache withSecurityCache(
      @Nullable final SecurityCache<String, String> securityCache) {
    this.cache = securityCache;
    return this;
  }

  /**
   * Returns the cached key by id and type or requests the keys from the JWKS URI of the identity
   * service.
   */
  public PublicKey getPublicKey(
      final KeyParameters keyParameters, final Map<String, String> requestParameters)
      throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
    assertNotNull(keyParameters.keyAlgorithm(), "keyAlgorithm must not be null.");
    assertHasText(keyParameters.keyId(), "keyId must not be null.");
    assertNotNull(keyParameters.keyUri(), "keyUrl must not be null.");
    return getPublicKey(
        keyParameters, requestParameters, new CacheKey(keyParameters.keyUri(), requestParameters));
  }

  public PublicKey getPublicKey(
      final KeyParameters keyParameters,
      final Map<String, String> requestParameters,
      final CacheKey cacheKey)
      throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
    assertNotNull(keyParameters.keyAlgorithm(), "keyAlgorithm must not be null.");
    assertHasText(keyParameters.keyId(), "keyId must not be null.");
    assertNotNull(keyParameters.keyUri(), "keyUrl must not be null.");

    final String key = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, cacheKey.toString());
    Optional<String> cachedJson = safeGet(key);
    JsonWebKeySet jwks;
    if (cachedJson.isPresent()) {
      jwks = tryParse(cachedJson.get());
      if (jwks == null) {
        LOGGER.debug("Cached JWKS entry was malformed — refetching");
        jwks = fetchAndCache(cacheKey, requestParameters, key);
      }
    } else {
      jwks = fetchAndCache(cacheKey, requestParameters, key);
    }

    if (jwks == null || jwks.getAll().isEmpty()) {
      LOGGER.error(
          "Retrieved no token keys from {} for the given header parameters.",
          LogSanitizer.sanitize(keyParameters.keyUri));
      return null;
    }

    for (JsonWebKey jwk : jwks.getAll()) {
      if (keyParameters.keyId.equals(jwk.getId())
          && jwk.getKeyAlgorithm().equals(keyParameters.keyAlgorithm)) {
        return jwk.getPublicKey();
      }
    }

    LOGGER.warn("No matching key with kid '{}' and algorithm '{}' found. Cached keys: {}."
        + " Note: JWKS entries with algorithms not supported by this library, or malformed entries,"
        + " are dropped at parse time — see earlier 'Skipping JWK entry' log lines for details.",
        LogSanitizer.sanitize(keyParameters.keyId), LogSanitizer.sanitize(keyParameters.keyAlgorithm),
        LogSanitizer.sanitize(jwks));
    throw new IllegalArgumentException("Key with kid " + keyParameters.keyId + " not found in JWKS.");
  }

  private JsonWebKeySet fetchAndCache(
      final CacheKey cacheKey, final Map<String, String> requestParameters, final String key)
      throws OAuth2ServiceException {
    final String jwksJson =
        getTokenKeyService().retrieveTokenKeys(cacheKey.keyUri(), requestParameters);
    if (jwksJson == null) {
      return null;
    }
    JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJson(jwksJson);
    // Only cache non-empty responses to avoid pinning a bad state.
    if (!jwks.getAll().isEmpty()) {
      safeSet(key, jwksJson, cacheConfiguration.getCacheDuration());
    }
    return jwks;
  }

  private JsonWebKeySet tryParse(final String jwksJson) {
    try {
      return JsonWebKeySetFactory.createFromJson(jwksJson);
    } catch (final RuntimeException e) {
      LOGGER.warn("Failed to parse cached JWKS JSON: {}", e.getMessage());
      return null;
    }
  }

  private Optional<String> safeGet(final String key) {
    try {
      return getCache().get(key);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.get failed for JWKS entry: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private void safeSet(final String key, final String value, final Duration ttl) {
    if (value == null) {
      return;
    }
    try {
      getCache().set(key, value, ttl);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.set failed for JWKS entry: {}", e.getMessage());
    }
  }

  private TokenKeyCacheConfiguration getCheckedConfiguration(
      final CacheConfiguration cacheConfiguration) {
    Assertions.assertNotNull(cacheConfiguration, "CacheConfiguration must not be null!");
    int size = cacheConfiguration.getCacheSize();
    Duration duration = cacheConfiguration.getCacheDuration();
    if (size < 1000) {
      int currentSize = getCacheConfiguration().getCacheSize();
      LOGGER.error(
          "Tried to set cache size to {} but the cache size must be 1000 or more. Cache size will remain at: {}",
          size,
          currentSize);
      size = currentSize;
    }
    if (duration.getSeconds() < 600) {
      Duration currentDuration = getCacheConfiguration().getCacheDuration();
      LOGGER.error(
          "Tried to set cache duration to {} seconds but the cache duration must be at least 600 seconds. Cache duration will remain at: {} seconds",
          duration.getSeconds(),
          currentDuration.getSeconds());
      duration = currentDuration;
    }
    if (duration.getSeconds() > 900) {
      Duration currentDuration = getCacheConfiguration().getCacheDuration();
      LOGGER.error(
          "Tried to set cache duration to {} seconds but the cache duration must be maximum 900 seconds. Cache duration will remain at: {} seconds",
          duration.getSeconds(),
          currentDuration.getSeconds());
      duration = currentDuration;
    }
    return TokenKeyCacheConfiguration.getInstance(
        duration, size, cacheConfiguration.isCacheStatisticsEnabled());
  }

  private SecurityCache<String, String> getCache() {
    SecurityCache<String, String> local = cache;
    if (local == null) {
      Caffeine<Object, Object> builder =
          Caffeine.newBuilder()
              .maximumSize(cacheConfiguration.getCacheSize())
              .expireAfterWrite(cacheConfiguration.getCacheDuration())
              .ticker(ticker);
      if (cacheConfiguration.isCacheStatisticsEnabled()) {
        builder.recordStats();
      }
      Cache<String, String> caffeine = builder.build();
      local = new CaffeineSecurityCache(caffeine);
      cache = local;
    }
    return local;
  }

  private OAuth2TokenKeyService getTokenKeyService() {
    if (tokenKeyService == null) {
      this.tokenKeyService = new DefaultOAuth2TokenKeyService();
    }
    return tokenKeyService;
  }

  @Nonnull
  @Override
  public CacheConfiguration getCacheConfiguration() {
    return cacheConfiguration;
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

  @Override
  @Nullable
  public Object getCacheStatistics() {
    if (!cacheConfiguration.isCacheStatisticsEnabled()) {
      return null;
    }
    SecurityCache<String, String> local = getCache();
    if (local instanceof CaffeineSecurityCache csc) {
      return csc.unwrap().stats();
    }
    return null;
  }

  /** For tests: exposes the SecurityCache in use. Package-private on purpose. */
  SecurityCache<String, String> internalCacheForTests() {
    return getCache();
  }

  /** Testing hook that lets a caller replace the cache with a {@link NoOpSecurityCache}. */
  OAuth2TokenKeyServiceWithCache withDisabledCacheForTests() {
    this.cache = new NoOpSecurityCache<>();
    return this;
  }

  record CacheKey(URI keyUri, Map<String, String> params) {
    @Override
    public String toString() {
      String paramString =
          params.entrySet().stream()
              .filter(e -> e.getValue() != null)
              .map(e -> e.getKey() + ":" + e.getValue())
              .collect(Collectors.joining("|"));

      return "url:%s|%s".formatted(keyUri, paramString);
    }
  }

  record KeyParameters(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri) {}
}
