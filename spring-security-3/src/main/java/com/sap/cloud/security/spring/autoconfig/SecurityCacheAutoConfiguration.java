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
 *   <li>A JSR-107 {@link javax.cache.CacheManager} bean holding a cache with the same name.
 *   <li>Nothing — the library falls back to its in-memory Caffeine cache.
 * </ol>
 *
 * <p>The token-client SPI and the java-security JWKS/OIDC caches will pick up this bean via their
 * respective configuration hooks in {@link
 * com.sap.cloud.security.spring.autoconfig.XsuaaTokenFlowAutoConfiguration} and
 * {@link com.sap.cloud.security.spring.autoconfig.HybridIdentityServicesAutoConfiguration}.
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
      final org.springframework.beans.factory.BeanFactory beanFactory,
      final org.springframework.core.env.Environment env) {
    String cacheName =
        env.getProperty(DEFAULT_CACHE_NAME_PROPERTY, DEFAULT_CACHE_NAME);

    // 1) Spring CacheManager
    CacheManager springMgr = springCacheManagerProvider.getIfAvailable();
    if (springMgr != null) {
      Cache spring = springMgr.getCache(cacheName);
      if (spring != null) {
        logger.info(
            "Wiring SecurityCache to Spring CacheManager cache '{}'",
            cacheName);
        return new SpringCacheSecurityCache(spring);
      }
      logger.debug(
          "Spring CacheManager is present but has no cache named '{}' — falling through",
          cacheName);
    }

    // 2) JSR-107 (JCache) CacheManager — optional; only wired if the class is on the classpath.
    try {
      Class<?> jcacheClass = Class.forName("javax.cache.CacheManager");
      Object jcacheMgr;
      try {
        jcacheMgr = beanFactory.getBean(jcacheClass);
      } catch (final org.springframework.beans.factory.NoSuchBeanDefinitionException nsb) {
        jcacheMgr = null;
      }
      if (jcacheMgr != null) {
        return new JCacheSecurityCacheAdapterFactory(cacheName).build(jcacheMgr);
      }
    } catch (final ClassNotFoundException e) {
      // javax.cache-api not on classpath — ignore.
    }

    // 3) Nothing — fall back to no-op so we don't accidentally shadow the library's built-in cache.
    logger.info(
        "sap.security.cache.distributed.enabled=true but no Spring CacheManager cache named '{}' "
            + "and no javax.cache.CacheManager bean was found. Falling back to library default.",
        cacheName);
    return new com.sap.cloud.security.cache.NoOpSecurityCache<>();
  }

  /**
   * Reflective adapter for JCache. Kept in a nested class so this auto-config compiles even when
   * javax.cache-api is not on the classpath.
   */
  static final class JCacheSecurityCacheAdapterFactory {
    private final String cacheName;

    JCacheSecurityCacheAdapterFactory(final String cacheName) {
      this.cacheName = cacheName;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    SecurityCache build(final Object jcacheManager) {
      try {
        // We only reach this branch when javax.cache.CacheManager is present.
        java.lang.reflect.Method getCache =
            jcacheManager.getClass().getMethod("getCache", String.class, Class.class, Class.class);
        Object cache = getCache.invoke(jcacheManager, cacheName, String.class, String.class);
        if (cache == null) {
          return new com.sap.cloud.security.cache.NoOpSecurityCache<>();
        }
        Class<?> adapterClass =
            Class.forName("com.sap.cloud.security.cache.jcache.JCacheSecurityCache");
        return (SecurityCache)
            adapterClass
                .getConstructor(Class.forName("javax.cache.Cache"))
                .newInstance(cache);
      } catch (final ReflectiveOperationException e) {
        return new com.sap.cloud.security.cache.NoOpSecurityCache<>();
      }
    }
  }
}
