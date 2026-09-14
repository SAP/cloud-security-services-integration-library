/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache.caffeine;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.util.LogSanitizer;
import jakarta.annotation.Nonnull;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link SecurityCache} implementation backed by an in-memory Caffeine cache. This is the default
 * cache used by the library when no distributed adapter is wired up.
 *
 * <p>Behavior:
 *
 * <ul>
 *   <li>{@link #set(String, String, Duration)} ignores the per-entry TTL and stores the value with
 *       the eviction policy configured on the underlying Caffeine cache (expire-after-write from
 *       {@link CacheConfiguration#getCacheDuration()}). Distributed adapters (e.g. Spring)
 *       behave the same way — per-entry TTLs are configured on the cache infrastructure, not per
 *       call.
 *   <li>All operations are wrapped in a try/catch so that a broken cache never causes the caller
 *       to fail. See {@link SecurityCache} for the contract.
 * </ul>
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * CaffeineSecurityCache cache = CaffeineSecurityCache.forConfiguration(
 *     TokenCacheConfiguration.defaultConfiguration());
 * DefaultOAuth2TokenService service = new DefaultOAuth2TokenService(
 *     httpClient, TokenCacheConfiguration.defaultConfiguration(), cache);
 * }</pre>
 *
 * @since 4.1.0
 */
public final class CaffeineSecurityCache implements SecurityCache<String, String> {

  private static final Logger LOGGER = LoggerFactory.getLogger(CaffeineSecurityCache.class);

  private final Cache<String, String> delegate;

  /** For testing only — allows injecting a custom ticker to advance time deterministically. */
  CaffeineSecurityCache(
      final int maximumSize, final Duration expireAfterWrite, @Nonnull final Ticker ticker) {
    this.delegate =
        Caffeine.newBuilder()
            .maximumSize(maximumSize)
            .expireAfterWrite(expireAfterWrite)
            .ticker(ticker)
            .build();
  }

  /** Creates a Caffeine-backed cache with the given size and expire-after-write duration. */
  public CaffeineSecurityCache(final int maximumSize, final Duration expireAfterWrite) {
    this(maximumSize, expireAfterWrite, Ticker.systemTicker());
  }

  /**
   * Wraps an already-configured Caffeine cache. Useful when callers want to reuse a project-wide
   * Caffeine instance (e.g. one that records statistics or uses a same-thread executor).
   */
  public CaffeineSecurityCache(@Nonnull final Cache<String, String> preBuilt) {
    this.delegate = preBuilt;
  }

  /** Convenience factory that reads size and duration from {@link CacheConfiguration}. */
  public static CaffeineSecurityCache forConfiguration(
      @Nonnull final CacheConfiguration cacheConfiguration) {
    return new CaffeineSecurityCache(
        cacheConfiguration.getCacheSize(), cacheConfiguration.getCacheDuration());
  }

  @Nonnull
  @Override
  public Optional<String> get(@Nonnull final String key) {
    try {
      return Optional.ofNullable(delegate.getIfPresent(key));
    } catch (final RuntimeException e) {
      LOGGER.warn("CaffeineSecurityCache.get failed for key {}: {}", LogSanitizer.sanitize(key), e.getMessage());
      return Optional.empty();
    }
  }

  @Override
  public void set(@Nonnull final String key, @Nonnull final String value, final Duration ttl) {
    try {
      // Caffeine uses cache-wide expiration; per-entry ttl argument is intentionally ignored.
      delegate.put(key, value);
    } catch (final RuntimeException e) {
      LOGGER.warn("CaffeineSecurityCache.set failed for key {}: {}", LogSanitizer.sanitize(key), e.getMessage());
    }
  }

  @Override
  public void delete(@Nonnull final String key) {
    try {
      delegate.invalidate(key);
    } catch (final RuntimeException e) {
      LOGGER.warn("CaffeineSecurityCache.delete failed for key {}: {}", LogSanitizer.sanitize(key), e.getMessage());
    }
  }

  @Override
  public void clear() {
    try {
      delegate.invalidateAll();
    } catch (final RuntimeException e) {
      LOGGER.warn("CaffeineSecurityCache.clear failed: {}", e.getMessage());
    }
  }

  /** @return the underlying Caffeine cache — for statistics or diagnostics only. */
  public Cache<String, String> unwrap() {
    return delegate;
  }
}
