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
 * </ol>
 *
 * <p>If none of the above resolves to a real backing store the application context fails to start
 * with an {@link IllegalStateException}. Silently falling back to a no-op cache would defeat the
 * library's built-in Caffeine cache, so this class fails fast rather than run without any cache at
 * all.
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

    try {
      Class<?> jcacheClass = Class.forName("javax.cache.CacheManager");
      Object jcacheMgr;
      try {
        jcacheMgr = beanFactory.getBean(jcacheClass);
      } catch (final org.springframework.beans.factory.NoSuchBeanDefinitionException nsb) {
        jcacheMgr = null;
      }
      if (jcacheMgr != null) {
        SecurityCache adapter = new JCacheSecurityCacheAdapterFactory(cacheName).build(jcacheMgr);
        if (adapter != null) {
          logger.info(
              "Wiring SecurityCache to JCache CacheManager cache '{}'",
              cacheName);
          return adapter;
        }
        throw new IllegalStateException(
            "sap.security.cache.distributed.enabled=true and a javax.cache.CacheManager bean is"
                + " present, but no cache named '"
                + cacheName
                + "' with <String, String> could be resolved. Provide a matching cache, override"
                + " sap.security.cache.distributed.cache-name, or set enabled=false.");
      }
    } catch (final ClassNotFoundException e) {
      // javax.cache-api not on classpath — ignore.
    }

    throw new IllegalStateException(
        "sap.security.cache.distributed.enabled=true but no backing store was found. Provide"
            + " either a SecurityCache<String,String> bean, a Spring CacheManager bean holding a"
            + " cache named '"
            + cacheName
            + "', or a javax.cache.CacheManager bean holding one. Alternatively set"
            + " sap.security.cache.distributed.enabled=false to keep using the library's built-in"
            + " Caffeine cache.");
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
        java.lang.reflect.Method getCache =
            jcacheManager.getClass().getMethod("getCache", String.class, Class.class, Class.class);
        Object cache = getCache.invoke(jcacheManager, cacheName, String.class, String.class);
        if (cache == null) {
          return null;
        }
        Class<?> adapterClass =
            Class.forName("com.sap.cloud.security.cache.jcache.JCacheSecurityCache");
        return (SecurityCache)
            adapterClass
                .getConstructor(Class.forName("javax.cache.Cache"))
                .newInstance(cache);
      } catch (final ReflectiveOperationException e) {
        return null;
      }
    }
  }
}
