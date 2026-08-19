/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.cache;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.util.LogSanitizer;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;

/**
 * {@link SecurityCache} adapter over a Spring {@link org.springframework.cache.Cache}. Plug in any
 * Spring Cache abstraction (Caffeine, Redis, Hazelcast, ...) to share the SAP Cloud
 * Security caches across processes.
 *
 * <h2>TTL handling</h2>
 *
 * Spring's {@code Cache} interface has no per-entry TTL. This adapter therefore ignores the {@code
 * ttl} argument and lets the underlying cache implementation apply its own expiration policy
 * (typically configured on the {@code CacheManager}).
 *
 * @since 4.1.0
 */
public final class SpringCacheSecurityCache implements SecurityCache<String, String> {

  private static final Logger LOGGER = LoggerFactory.getLogger(SpringCacheSecurityCache.class);

  private final Cache delegate;

  public SpringCacheSecurityCache(final Cache delegate) {
    this.delegate = delegate;
  }

  @Override
  public Optional<String> get(final String key) {
    try {
      Cache.ValueWrapper wrapper = delegate.get(key);
      if (wrapper == null) {
        return Optional.empty();
      }
      Object v = wrapper.get();
      return v instanceof String s ? Optional.of(s) : Optional.empty();
    } catch (final RuntimeException e) {
      LOGGER.warn("SpringCache.get failed for {}: {}", LogSanitizer.sanitize(key), e.getMessage());
      return Optional.empty();
    }
  }

  @Override
  public void set(final String key, final String value, final Duration ttl) {
    try {
      delegate.put(key, value);
    } catch (final RuntimeException e) {
      LOGGER.warn("SpringCache.put failed for {}: {}", LogSanitizer.sanitize(key), e.getMessage());
    }
  }

  @Override
  public void delete(final String key) {
    try {
      delegate.evict(key);
    } catch (final RuntimeException e) {
      LOGGER.warn("SpringCache.evict failed for {}: {}", LogSanitizer.sanitize(key), e.getMessage());
    }
  }

  @Override
  public void clear() {
    try {
      delegate.clear();
    } catch (final RuntimeException e) {
      LOGGER.warn("SpringCache.clear failed: {}", e.getMessage());
    }
  }
}
