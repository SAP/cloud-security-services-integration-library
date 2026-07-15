/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.cache;

import com.sap.cloud.security.config.CacheConfiguration;
import jakarta.annotation.Nonnull;
import java.time.Duration;

/**
 * {@link CacheConfiguration} for the opt-in {@link TokenDecodeCache}. Disabled by default; enable
 * by calling {@link #enabled(Duration)} or {@link #enabled(Duration, int)}.
 */
public final class TokenDecodeCacheConfiguration implements CacheConfiguration {

  private static final TokenDecodeCacheConfiguration DISABLED =
      new TokenDecodeCacheConfiguration(Duration.ZERO, 0, true);

  private final Duration cacheDuration;
  private final int cacheSize;
  private final boolean disabled;

  private TokenDecodeCacheConfiguration(
      final Duration cacheDuration, final int cacheSize, final boolean disabled) {
    this.cacheDuration = cacheDuration;
    this.cacheSize = cacheSize;
    this.disabled = disabled;
  }

  /** Default: disabled. */
  public static TokenDecodeCacheConfiguration disabled() {
    return DISABLED;
  }

  /**
   * Enables the cache. Each entry additionally uses the token's {@code exp} claim to cap its TTL —
   * this value only sets the <em>upper bound</em>.
   *
   * @param maxCacheDuration ceiling for how long any single entry can be cached.
   */
  public static TokenDecodeCacheConfiguration enabled(final Duration maxCacheDuration) {
    return enabled(maxCacheDuration, 10_000);
  }

  /** Enables the cache with an explicit size limit for the default in-memory implementation. */
  public static TokenDecodeCacheConfiguration enabled(
      final Duration maxCacheDuration, final int cacheSize) {
    if (maxCacheDuration == null || maxCacheDuration.isZero() || maxCacheDuration.isNegative()) {
      throw new IllegalArgumentException("maxCacheDuration must be positive");
    }
    if (cacheSize <= 0) {
      throw new IllegalArgumentException("cacheSize must be positive");
    }
    return new TokenDecodeCacheConfiguration(maxCacheDuration, cacheSize, false);
  }

  @Nonnull
  @Override
  public Duration getCacheDuration() {
    return cacheDuration;
  }

  @Override
  public int getCacheSize() {
    return cacheSize;
  }

  @Override
  public boolean isCacheDisabled() {
    return disabled;
  }

  @Override
  public boolean isCacheStatisticsEnabled() {
    return false;
  }
}
