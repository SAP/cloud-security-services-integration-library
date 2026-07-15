/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache.jcache;

import com.sap.cloud.security.cache.SecurityCache;
import jakarta.annotation.Nonnull;
import java.time.Duration;
import java.util.Optional;
import javax.cache.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link SecurityCache} adapter over a JSR-107 (JCache) {@link Cache}. Plug in a JCache-compatible
 * provider (Caffeine JCache, Ehcache, Hazelcast, Redisson, ...) to share the SAP Cloud Security
 * caches across processes.
 *
 * <h2>TTL handling</h2>
 *
 * The per-entry TTL passed to {@link #set(String, String, Duration)} is <strong>ignored</strong> —
 * JCache expiration is controlled by the {@link javax.cache.expiry.ExpiryPolicy} configured on the
 * {@link javax.cache.CacheManager}. Configure your expiry policy to something similar to the
 * caches' own {@code cacheDuration} (10 minutes for tokens, 10 for JWKS/OIDC by default) and you
 * are done.
 *
 * <p>Rationale: JCache providers vary in whether they honor per-put TTLs. Ignoring the argument and
 * pointing users at {@code ExpiryPolicy} gives predictable behavior across implementations.
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * CacheManager mgr = Caching.getCachingProvider().getCacheManager();
 * Cache<String, String> jcache = mgr.getCache("sap-security", String.class, String.class);
 * SecurityCache<String, String> adapter = new JCacheSecurityCache(jcache);
 * DefaultOAuth2TokenService svc = new DefaultOAuth2TokenService(
 *     httpClient, TokenCacheConfiguration.defaultConfiguration(), adapter);
 * }</pre>
 *
 * @since 4.1.0
 */
public final class JCacheSecurityCache implements SecurityCache<String, String> {

  private static final Logger LOGGER = LoggerFactory.getLogger(JCacheSecurityCache.class);

  private final Cache<String, String> delegate;

  public JCacheSecurityCache(@Nonnull final Cache<String, String> delegate) {
    this.delegate = delegate;
  }

  @Nonnull
  @Override
  public Optional<String> get(@Nonnull final String key) {
    try {
      return Optional.ofNullable(delegate.get(key));
    } catch (final RuntimeException e) {
      LOGGER.warn("JCache.get failed for {}: {}", key, e.getMessage());
      return Optional.empty();
    }
  }

  @Override
  public void set(@Nonnull final String key, @Nonnull final String value, final Duration ttl) {
    try {
      delegate.put(key, value);
    } catch (final RuntimeException e) {
      LOGGER.warn("JCache.put failed for {}: {}", key, e.getMessage());
    }
  }

  @Override
  public void delete(@Nonnull final String key) {
    try {
      delegate.remove(key);
    } catch (final RuntimeException e) {
      LOGGER.warn("JCache.remove failed for {}: {}", key, e.getMessage());
    }
  }

  @Override
  public void clear() {
    try {
      // Prefer JCache's per-key model over clear(); a shared JCache typically holds entries
      // from other consumers too. The library keeps its own key prefix (CacheKeys.prefix()) so
      // an operator can also flush only library-owned entries at the infra level.
      delegate.clear();
    } catch (final RuntimeException e) {
      LOGGER.warn("JCache.clear failed: {}", e.getMessage());
    }
  }
}
