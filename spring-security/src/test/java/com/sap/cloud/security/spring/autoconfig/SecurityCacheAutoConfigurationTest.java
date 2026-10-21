/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.spring.cache.SpringCacheSecurityCache;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class SecurityCacheAutoConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(AutoConfigurations.of(SecurityCacheAutoConfiguration.class));

  @Test
  void notEnabled_noBean() {
    runner.run(ctx -> assertThat(ctx).doesNotHaveBean(SecurityCache.class));
  }

  @Test
  void enabled_withUserSuppliedSecurityCacheBean_isPreferred() {
    runner
        .withPropertyValues("sap.security.cache.distributed.enabled=true")
        .withUserConfiguration(UserCacheConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(SecurityCache.class);
              SecurityCache<?, ?> cache = ctx.getBean(SecurityCache.class);
              assertThat(cache).isInstanceOf(MarkerCache.class);
            });
  }

  @Test
  void enabled_withSpringCacheManager_wrapsNamedCache() {
    runner
        .withPropertyValues("sap.security.cache.distributed.enabled=true")
        .withUserConfiguration(SpringCacheManagerConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(SecurityCache.class);
              SecurityCache<?, ?> cache = ctx.getBean(SecurityCache.class);
              assertThat(cache).isInstanceOf(SpringCacheSecurityCache.class);
            });
  }

  @Test
  void enabled_withSpringCacheManager_customCacheName_wrapsNamedCache() {
    runner
        .withPropertyValues(
            "sap.security.cache.distributed.enabled=true",
            "sap.security.cache.distributed.cache-name=custom-cache")
        .withUserConfiguration(CustomNameSpringCacheManagerConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(SecurityCache.class);
              SecurityCache<?, ?> cache = ctx.getBean(SecurityCache.class);
              assertThat(cache).isInstanceOf(SpringCacheSecurityCache.class);
            });
  }

  @Test
  void enabled_springCacheManagerWithoutNamedCache_fallsThrough_thenFailsFast() {
    runner
        .withPropertyValues(
            "sap.security.cache.distributed.enabled=true",
            "sap.security.cache.distributed.cache-name=absent")
        .withUserConfiguration(SpringCacheManagerConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure()).hasStackTraceContaining("no backing store");
            });
  }

  @Test
  void enabled_noCacheAvailable_failsFast() {
    runner
        .withPropertyValues("sap.security.cache.distributed.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure()).hasStackTraceContaining("no backing store");
            });
  }

  @Configuration
  static class UserCacheConfig {
    @Bean
    public SecurityCache<String, String> securityCache() {
      return new MarkerCache();
    }
  }

  @Configuration
  static class SpringCacheManagerConfig {
    @Bean
    public CacheManager cacheManager() {
      SimpleCacheManager mgr = new SimpleCacheManager();
      mgr.setCaches(java.util.List.of(new ConcurrentMapCache("sap-security")));
      mgr.afterPropertiesSet();
      return mgr;
    }
  }

  @Configuration
  static class CustomNameSpringCacheManagerConfig {
    @Bean
    public CacheManager cacheManager() {
      SimpleCacheManager mgr = new SimpleCacheManager();
      mgr.setCaches(java.util.List.of(new ConcurrentMapCache("custom-cache")));
      mgr.afterPropertiesSet();
      return mgr;
    }
  }

  private static class MarkerCache implements SecurityCache<String, String> {
    @Override
    public Optional<String> get(String key) {
      return Optional.empty();
    }

    @Override
    public void set(String key, String value, Duration ttl) {}

    @Override
    public void delete(String key) {}

    @Override
    public void clear() {}
  }
}
