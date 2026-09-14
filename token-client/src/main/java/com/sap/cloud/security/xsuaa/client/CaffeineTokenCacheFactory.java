/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.cache.caffeine.CaffeineSecurityCache;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import jakarta.annotation.Nonnull;
import java.util.Optional;

/**
 * Internal helper that builds a Caffeine-backed {@link SecurityCache} matching the token cache
 * knobs (statistics recording, same-thread executor for deterministic tests) that the previous
 * hand-rolled Caffeine cache exposed. Kept package-private on purpose.
 */
final class CaffeineTokenCacheFactory {

  private CaffeineTokenCacheFactory() {}

  static CaffeineSecurityCache build(
      @Nonnull final TokenCacheConfiguration cfg,
      @Nonnull final Ticker ticker,
      final boolean sameThreadCache) {
    Caffeine<Object, Object> builder =
        Caffeine.newBuilder()
            .maximumSize(cfg.getCacheSize())
            .ticker(ticker)
            .expireAfterWrite(cfg.getCacheDuration());
    if (sameThreadCache) {
      builder.executor(Runnable::run);
    }
    if (cfg.isCacheStatisticsEnabled()) {
      builder.recordStats();
    }
    Cache<String, String> cache = builder.build();
    return new CaffeineSecurityCache(cache);
  }

  /** Extracts the underlying Caffeine cache from a wrapped {@link SecurityCache}, if any. */
  static Optional<Cache<String, String>> unwrap(final SecurityCache<String, String> cache) {
    if (cache instanceof CaffeineSecurityCache csc) {
      return Optional.ofNullable(csc.unwrap());
    }
    return Optional.empty();
  }
}
