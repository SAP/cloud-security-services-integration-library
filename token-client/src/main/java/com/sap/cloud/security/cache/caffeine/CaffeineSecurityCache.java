/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache.caffeine;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.config.CacheConfiguration;
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
 *   <li>{@link #set(String, String, Duration)} honors the per-entry TTL via Caffeine's {@link
 *       Expiry} policy. A {@code null} TTL stores the entry with the cache-wide default duration.
 *       The TTL is carried in an internal, caller-transparent prefix on the stored value; entries
 *       written without that prefix (e.g. directly into a pre-built cache, or by an older library
 *       version) fall back to the cache-wide default.
 *   <li>Instances built from a pre-existing Caffeine cache (see the {@code preBuilt} constructor)
 *       manage expiration through that cache's own policy; the per-entry TTL argument is
 *       best-effort there.
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
 * @since 4.2.0
 */
public final class CaffeineSecurityCache implements SecurityCache<String, String> {

  private static final Logger LOGGER = LoggerFactory.getLogger(CaffeineSecurityCache.class);

  /** Separator between the internal TTL prefix and the stored value. */
  private static final char TTL_DELIMITER = '\u0000';

  /** Fallback duration for entries without a resolvable TTL prefix. */
  private static final Duration FALLBACK_TTL = Duration.ofHours(1);

  private final Cache<String, String> delegate;
  private final Duration defaultTtl;
  private final Expiry<Object, Object> expiry;

  /**
   * For testing only — allows injecting a custom ticker to advance time deterministically.
   *
   * @param maximumSize maximum number of entries
   * @param defaultTtl cache-wide TTL used when {@link #set} is called with a {@code null} TTL
   * @param ticker the time source used for expiration
   */
  CaffeineSecurityCache(
      final int maximumSize, final Duration defaultTtl, @Nonnull final Ticker ticker) {
    this(maximumSize, defaultTtl, ticker, false);
  }

  /**
   * Creates a Caffeine-backed cache with per-entry TTL support and an optional statistics
   * recording.
   *
   * @param maximumSize maximum number of entries
   * @param defaultTtl cache-wide TTL used when {@link #set} is called with a {@code null} TTL
   * @param ticker the time source used for expiration
   * @param recordStats whether Caffeine statistics should be recorded
   * @since 4.2.0
   */
  public CaffeineSecurityCache(
      final int maximumSize,
      final Duration defaultTtl,
      @Nonnull final Ticker ticker,
      final boolean recordStats) {
    this.defaultTtl = defaultTtl;
    this.expiry = Expiry.writing((key, value) -> Duration.ofNanos(ttlNanosFor((String) value)));
    Caffeine<Object, Object> builder =
        Caffeine.newBuilder()
            .maximumSize(maximumSize)
            .expireAfter(this.expiry)
            .ticker(ticker);
    if (recordStats) {
      builder.recordStats();
    }
    this.delegate = builder.build();
  }

  /** Creates a Caffeine-backed cache with the given size and default (cache-wide) duration. */
  public CaffeineSecurityCache(final int maximumSize, final Duration defaultTtl) {
    this(maximumSize, defaultTtl, Ticker.systemTicker());
  }

  /**
   * Wraps an already-configured Caffeine cache. Useful when callers want to reuse a project-wide
   * Caffeine instance (e.g. one that records statistics or uses a same-thread executor). Expiration
   * is managed by the wrapped cache's own policy; the per-entry TTL passed to {@link #set} is
   * best-effort in this mode.
   */
  public CaffeineSecurityCache(@Nonnull final Cache<String, String> preBuilt) {
    this.delegate = preBuilt;
    this.defaultTtl = null;
    this.expiry = Expiry.writing((key, value) -> FALLBACK_TTL);
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
      final String raw = delegate.getIfPresent(key);
      if (raw == null) {
        return Optional.empty();
      }
      return Optional.of(stripTtlPrefix(raw));
    } catch (final RuntimeException e) {
      // Key and exception message are not logged: cache keys and error
      // messages can carry request-derived data and must not end up in logs.
      LOGGER.warn("CaffeineSecurityCache.get failed - treating as cache miss", e);
      return Optional.empty();
    }
  }

  @Override
  public void set(@Nonnull final String key, @Nonnull final String value, final Duration ttl) {
    try {
      if (ttl == null || ttl.isZero() || ttl.isNegative()) {
        delegate.put(key, value);
      } else {
        delegate.put(key, String.valueOf(ttl.toNanos()) + TTL_DELIMITER + value);
      }
    } catch (final RuntimeException e) {
      LOGGER.warn("CaffeineSecurityCache.set failed - value not cached", e);
    }
  }

  @Override
  public void delete(@Nonnull final String key) {
    try {
      delegate.invalidate(key);
    } catch (final RuntimeException e) {
      LOGGER.warn("CaffeineSecurityCache.delete failed - key not removed", e);
    }
  }

  @Override
  public void clear() {
    try {
      delegate.invalidateAll();
    } catch (final RuntimeException e) {
      LOGGER.warn("CaffeineSecurityCache.clear failed - cache not cleared", e);
    }
  }

  /**
   * @return the underlying Caffeine cache — for statistics or diagnostics only. Note that values
   *     stored via {@link #set} carry an internal TTL prefix.
   */
  public Cache<String, String> unwrap() {
    return delegate;
  }

  /**
   * @return the expiration duration in nanoseconds for the given stored value: the per-entry TTL
   *     from the value's internal prefix if present, otherwise the cache-wide default.
   */
  private long ttlNanosFor(final String rawValue) {
    return parseTtlPrefix(rawValue)
        .orElseGet(() -> defaultTtl != null ? defaultTtl.toNanos() : FALLBACK_TTL.toNanos());
  }

  /**
   * Removes the internal TTL prefix from a stored value. Values without a well-formed prefix are
   * returned unchanged.
   */
  private static String stripTtlPrefix(final String rawValue) {
    if (parseTtlPrefix(rawValue).isPresent()) {
      return rawValue.substring(rawValue.indexOf(TTL_DELIMITER) + 1);
    }
    return rawValue;
  }

  /**
   * Parses the internal TTL prefix (a positive nanosecond count terminated by {@link
   * #TTL_DELIMITER}) from a stored value.
   */
  private static Optional<Long> parseTtlPrefix(final String rawValue) {
    final int idx = rawValue.indexOf(TTL_DELIMITER);
    if (idx <= 0) {
      return Optional.empty();
    }
    final String head = rawValue.substring(0, idx);
    for (int i = 0; i < head.length(); i++) {
      final char c = head.charAt(i);
      if (c < '0' || c > '9') {
        return Optional.empty();
      }
    }
    try {
      final long nanos = Long.parseLong(head);
      return nanos > 0 ? Optional.of(nanos) : Optional.empty();
    } catch (final NumberFormatException e) {
      return Optional.empty();
    }
  }
}
