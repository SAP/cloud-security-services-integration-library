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
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Decorates {@link OAuth2TokenKeyService} with a {@link SecurityCache}-backed cache, which gets
 * looked up before the identity service is requested via HTTP.
 *
 * <p>Since 4.2.0 the cache is expressed against the {@link SecurityCache} SPI. The cached value is
 * the raw JWKS JSON as returned by the identity service; the {@link JsonWebKeySet} is rebuilt on
 * every hit. That makes cached entries safe to share across processes at the cost of a small,
 * predictable per-hit CPU overhead.
 *
 * <p>Retrievals that fail with a stable client error (any 4xx response, e.g. an unknown zone id
 * answered with 404) are <em>negatively cached</em> for a short time ({@link #NEGATIVE_CACHE_TTL}):
 * within that window, further requests for the same key fail fast without a network call, so a
 * stream of invalid tokens cannot keep triggering HTTP requests. Transient failures — server
 * errors (5xx), timeouts, transport errors — are <em>not</em> negatively cached, so the next
 * request retries immediately. After a negative entry expires, the next request retries the
 * retrieval. Adapters that do not support per-entry TTLs keep the negative entry for the store's
 * own TTL instead.
 */
class OAuth2TokenKeyServiceWithCache implements Cacheable {
  private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2TokenKeyServiceWithCache.class);

  /** Marker stored in the cache to remember a failed JWKS retrieval (negative caching). */
  static final String NEGATIVE_CACHE_MARKER = "jwks-fetch-failed";

  /** How long a failed JWKS retrieval is remembered before the next request retries. */
  static final Duration NEGATIVE_CACHE_TTL = Duration.ofSeconds(30);

  private OAuth2TokenKeyService tokenKeyService;
  /**
   * Cache explicitly supplied by the caller via {@link #withSecurityCache}. Never invalidated by
   * {@link #withCacheConfiguration}.
   */
  private SecurityCache<String, String> explicitCache;
  /** Lazily created from {@link #cacheConfiguration} when no explicit cache is supplied. */
  private SecurityCache<String, String> builtCache;
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
   *
   * <p>This method only tunes the lazily created in-memory default cache. A cache explicitly
   * supplied via {@link #withSecurityCache} is not affected by this method, in any call order.
   */
  public OAuth2TokenKeyServiceWithCache withCacheConfiguration(
      final CacheConfiguration cacheConfiguration) {
    this.cacheConfiguration = getCheckedConfiguration(cacheConfiguration);
    // Force rebuild of the lazily created default cache next time it's needed.
    // An explicitly supplied cache (withSecurityCache) is intentionally left untouched.
    this.builtCache = null;
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
   * @since 4.2.0
   */
  public OAuth2TokenKeyServiceWithCache withSecurityCache(
      @Nullable final SecurityCache<String, String> securityCache) {
    this.explicitCache = securityCache;
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
      final String cached = cachedJson.get();
      if (NEGATIVE_CACHE_MARKER.equals(cached)) {
        // Negative cache hit: the last retrieval for this key failed. Fail fast without a
        // network call; the entry expires after NEGATIVE_CACHE_TTL and the next request retries.
        LOGGER.debug("Negative cache hit for JWKS key - failing fast without a network call");
        throw new OAuth2ServiceException(
            "Token keys retrieval failed previously and is negatively cached; will retry after a short delay");
      }
      jwks = tryParse(cached);
      if (jwks == null) {
        LOGGER.debug("Cached JWKS entry was malformed — refetching");
        jwks = singleFlightFetch(key, () -> fetchAndCache(cacheKey, requestParameters, key));
      }
    } else {
      jwks = singleFlightFetch(key, () -> fetchAndCache(cacheKey, requestParameters, key));
    }

    if (jwks == null || jwks.getAll().isEmpty()) {
      // The key URI is not logged: it is request-derived and can carry
      // query parameters that must not end up in logs.
      LOGGER.error(
          "Retrieved no token keys from the JWKS endpoint for the given key parameters");
      return null;
    }

    for (JsonWebKey jwk : jwks.getAll()) {
      if (keyParameters.keyId.equals(jwk.getId())
          && jwk.getKeyAlgorithm().equals(keyParameters.keyAlgorithm)) {
        return jwk.getPublicKey();
      }
    }

    // keyId / algorithm are not logged: they come from the token's header and
    // are user-provided values.
    LOGGER.warn("No matching key found in the JWKS for the requested keyId and algorithm."
        + " Note: JWKS entries with algorithms not supported by this library, or malformed entries,"
        + " are dropped at parse time - see earlier 'Skipping JWK entry' log lines for details.");
    throw new IllegalArgumentException("Key with kid " + keyParameters.keyId + " not found in JWKS.");
  }

  private JsonWebKeySet fetchAndCache(
      final CacheKey cacheKey, final Map<String, String> requestParameters, final String key)
      throws OAuth2ServiceException {
    final String jwksJson;
    try {
      jwksJson = getTokenKeyService().retrieveTokenKeys(cacheKey.keyUri(), requestParameters);
    } catch (final OAuth2ServiceException e) {
      // Negative caching: only stable client errors (4xx) are remembered, briefly, so repeated
      // requests for a permanently invalid key (e.g. an unknown zone id answered with 404) fail
      // fast instead of each making a network call. Transient failures (5xx, timeouts, transport
      // errors) are not cached, so the next request retries immediately.
      if (isStableFailure(e)) {
        safeSet(key, NEGATIVE_CACHE_MARKER, NEGATIVE_CACHE_TTL);
      }
      throw e;
    }
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

  /**
   * A failed retrieval is negatively cached only if the identity service answered with a stable
   * client error (4xx), e.g. an unknown zone id answered with 404. Such a key will keep failing
   * until it is corrected, so failing fast for a short window is safe. Transient failures —
   * server errors (5xx), timeouts, connection problems, and other non-HTTP errors (no status
   * code) — must not delay the next retry, so they are never negatively cached.
   */
  private static boolean isStableFailure(final OAuth2ServiceException e) {
    // A null status code means no HTTP response was received (or the exception was created
    // without one) — treated as transient.
    final Integer statusCode = e.getHttpStatusCode();
    return statusCode != null && statusCode >= 400 && statusCode < 500;
  }

  private final ConcurrentHashMap<String, CompletableFuture<JsonWebKeySet>> inFlight =
      new ConcurrentHashMap<>();

  /**
   * Collapses concurrent fetches for the same cache key into a single HTTP call. The first
   * requester performs the retrieval (and the cache write); concurrent waiters receive the same
   * result. This mirrors the single-flight behavior of the outbound token cache and prevents a
   * burst of parallel JWKS requests after a cache eviction or a rolling deploy.
   */
  private JsonWebKeySet singleFlightFetch(
      final String key, final CheckedSupplier<JsonWebKeySet> fetcher)
      throws OAuth2ServiceException {
    CompletableFuture<JsonWebKeySet> ours = new CompletableFuture<>();
    CompletableFuture<JsonWebKeySet> existing = inFlight.putIfAbsent(key, ours);
    if (existing != null) {
      try {
        return existing.get();
      } catch (final InterruptedException ie) {
        Thread.currentThread().interrupt();
        throw OAuth2ServiceException.builder("Interrupted while waiting for in-flight JWKS fetch")
            .withUri(URI.create("about:blank"))
            .build();
      } catch (final ExecutionException ee) {
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
    try {
      JsonWebKeySet fetched = fetcher.get();
      ours.complete(fetched);
      return fetched;
    } catch (final OAuth2ServiceException | RuntimeException e) {
      ours.completeExceptionally(e);
      throw e;
    } finally {
      inFlight.remove(key, ours);
    }
  }

  @FunctionalInterface
  private interface CheckedSupplier<T> {
    T get() throws OAuth2ServiceException;
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
    SecurityCache<String, String> explicit = explicitCache;
    if (explicit != null) {
      return explicit;
    }
    SecurityCache<String, String> local = builtCache;
    if (local == null) {
      local =
          new CaffeineSecurityCache(
              cacheConfiguration.getCacheSize(),
              cacheConfiguration.getCacheDuration(),
              ticker,
              cacheConfiguration.isCacheStatisticsEnabled());
      builtCache = local;
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
    // Clear the effective cache without triggering creation of the default cache.
    SecurityCache<String, String> local = explicitCache != null ? explicitCache : builtCache;
    if (local != null) {
      try {
        local.clear();
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
    this.explicitCache = new NoOpSecurityCache<>();
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
