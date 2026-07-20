/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.spring.cache.SpringCacheSecurityCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Auto-configuration that wires a shared {@link SecurityCache} into the SAP Cloud Security caches
 * when distributed caching is enabled. Off by default; enable via {@code
 * sap.security.cache.distributed.enabled=true}.
 *
 * <p>Discovery order (first match wins):
 *
 * <ol>
 *   <li>A user-supplied {@link SecurityCache}<{@code String,String}> bean.
 *   <li>A Spring {@link CacheManager} bean holding a cache named {@code sap-security} (or the name
 *       configured via {@code sap.security.cache.distributed.cache-name}).
 * </ol>
 *
 * <p>If neither resolves, the application context fails to start with an
 * {@link IllegalStateException}. Silently falling back to a no-op cache would defeat the library's
 * built-in Caffeine cache, so this class fails fast rather than run without any cache at all.
 *
 * <p>Any cache backend beyond Spring's own abstraction (Redis, Hazelcast, ...)
 * is supported by declaring a custom {@link SecurityCache} bean — see the README for a
 * copy-pasteable snippet.
 *
 * @since 4.1.0
 */
@Configuration
@ConditionalOnProperty(prefix = "sap.security.cache.distributed", name = "enabled", havingValue = "true")
public class SecurityCacheAutoConfiguration {

  static final String DEFAULT_CACHE_NAME_PROPERTY = "sap.security.cache.distributed.cache-name";
  static final String DEFAULT_CACHE_NAME = "sap-security";

  private final Logger logger = LoggerFactory.getLogger(getClass());

  @Bean
  @ConditionalOnMissingBean(SecurityCache.class)
  @SuppressWarnings("rawtypes")
  public SecurityCache securityCache(
      final ObjectProvider<CacheManager> springCacheManagerProvider,
      final org.springframework.core.env.Environment env) {
    String cacheName = env.getProperty(DEFAULT_CACHE_NAME_PROPERTY, DEFAULT_CACHE_NAME);

    CacheManager springMgr = springCacheManagerProvider.getIfAvailable();
    if (springMgr != null) {
      Cache spring = springMgr.getCache(cacheName);
      if (spring != null) {
        logger.info("Wiring SecurityCache to Spring CacheManager cache '{}'", cacheName);
        return new SpringCacheSecurityCache(spring);
      }
    }

    throw new IllegalStateException(
        "sap.security.cache.distributed.enabled=true but no backing store was found. Provide"
            + " either a SecurityCache<String,String> bean or a Spring CacheManager bean holding a"
            + " cache named '"
            + cacheName
            + "'. Alternatively set sap.security.cache.distributed.enabled=false to keep using the"
            + " library's built-in Caffeine cache.");
  }
}
