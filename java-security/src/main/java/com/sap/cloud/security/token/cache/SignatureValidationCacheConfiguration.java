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
 * {@link CacheConfiguration} for the opt-in signature validation cache. Disabled by default; enable
 * via {@link #enabled(Duration, byte[])}.
 */
public final class SignatureValidationCacheConfiguration implements CacheConfiguration {

  private static final SignatureValidationCacheConfiguration DISABLED =
      new SignatureValidationCacheConfiguration(Duration.ZERO, 0, true, new byte[0]);

  private final Duration cacheDuration;
  private final int cacheSize;
  private final boolean disabled;
  private final byte[] ikm;

  private SignatureValidationCacheConfiguration(
      final Duration cacheDuration,
      final int cacheSize,
      final boolean disabled,
      final byte[] ikm) {
    this.cacheDuration = cacheDuration;
    this.cacheSize = cacheSize;
    this.disabled = disabled;
    this.ikm = ikm == null ? new byte[0] : ikm.clone();
  }

  /** Default: disabled. */
  public static SignatureValidationCacheConfiguration disabled() {
    return DISABLED;
  }

  /**
   * Enables the cache with the given TTL cap and HMAC input keying material (IKM). The IKM should
   * be derived from per-application secrets (typically {@code clientId || clientSecret} or {@code
   * clientId || sha256(certPem)}) so that all pods of the same application produce the same HMAC
   * for the same cache entry — and no other application can forge one.
   *
   * @param maxCacheDuration ceiling for how long any single validation result is trusted from the
   *     cache
   * @param ikm application-specific keying material; must be non-empty
   */
  public static SignatureValidationCacheConfiguration enabled(
      final Duration maxCacheDuration, final byte[] ikm) {
    return enabled(maxCacheDuration, 10_000, ikm);
  }

  /** Enables the cache with an explicit size limit for the default in-memory implementation. */
  public static SignatureValidationCacheConfiguration enabled(
      final Duration maxCacheDuration, final int cacheSize, final byte[] ikm) {
    if (maxCacheDuration == null || maxCacheDuration.isZero() || maxCacheDuration.isNegative()) {
      throw new IllegalArgumentException("maxCacheDuration must be positive");
    }
    if (cacheSize <= 0) {
      throw new IllegalArgumentException("cacheSize must be positive");
    }
    if (ikm == null || ikm.length == 0) {
      throw new IllegalArgumentException("ikm must be non-empty");
    }
    return new SignatureValidationCacheConfiguration(maxCacheDuration, cacheSize, false, ikm);
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

  /** Returns a defensive copy of the IKM. */
  public byte[] getIkm() {
    return ikm.clone();
  }
}
