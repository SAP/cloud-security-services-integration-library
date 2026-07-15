/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import static org.assertj.core.api.Assertions.assertThat;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.token.cache.SignatureValidationCache;
import com.sap.cloud.security.token.cache.TokenDecodeCache;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class TokenValidationCachesAutoConfigurationTest {

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  SecurityCacheAutoConfiguration.class,
                  TokenValidationCachesAutoConfiguration.class))
          .withUserConfiguration(EnvVarStubConfig.class);

  @Test
  void bothDisabled_noBeans() {
    runner.run(
        ctx -> {
          assertThat(ctx).doesNotHaveBean(TokenDecodeCache.class);
          assertThat(ctx).doesNotHaveBean(SignatureValidationCache.class);
        });
  }

  @Test
  void tokenDecodeEnabled_defaultDuration_producesBean() {
    runner
        .withPropertyValues("sap.security.cache.token-decode.enabled=true")
        .run(ctx -> assertThat(ctx).hasSingleBean(TokenDecodeCache.class));
  }

  @Test
  void tokenDecodeEnabled_customDuration_producesBean() {
    runner
        .withPropertyValues(
            "sap.security.cache.token-decode.enabled=true",
            "sap.security.cache.token-decode.duration=PT10M")
        .run(ctx -> assertThat(ctx).hasSingleBean(TokenDecodeCache.class));
  }

  @Test
  void tokenDecodeEnabled_invalidDuration_failsFast() {
    runner
        .withPropertyValues(
            "sap.security.cache.token-decode.enabled=true",
            "sap.security.cache.token-decode.duration=nope")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .hasStackTraceContaining("Invalid ISO-8601 duration");
            });
  }

  @Test
  void tokenDecodeEnabled_reusesSharedSecurityCache() {
    runner
        .withPropertyValues(
            "sap.security.cache.distributed.enabled=true",
            "sap.security.cache.token-decode.enabled=true")
        .withUserConfiguration(SharedCacheConfig.class, EnvVarStubConfig.class)
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(TokenDecodeCache.class);
              assertThat(ctx).hasSingleBean(SecurityCache.class);
            });
  }

  @Test
  void signatureEnabled_missingIkmEnvVarProperty_failsFast() {
    runner
        .withPropertyValues("sap.security.cache.signature.enabled=true")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .hasStackTraceContaining("ikm-env-var is not set");
            });
  }

  @Test
  void signatureEnabled_ikmEnvVarProperty_butEnvVarBlank_failsFast() {
    runner
        .withPropertyValues(
            "sap.security.cache.signature.enabled=true",
            "sap.security.cache.signature.ikm-env-var=UNKNOWN_ENV_VAR_XYZ")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .hasStackTraceContaining("not set or is empty");
            });
  }

  @Test
  void signatureEnabled_ikmProvidedByStubEnvReader_producesBean() {
    runner
        .withPropertyValues(
            "sap.security.cache.signature.enabled=true",
            "sap.security.cache.signature.ikm-env-var=STUBBED_IKM")
        .run(ctx -> assertThat(ctx).hasSingleBean(SignatureValidationCache.class));
  }

  @Test
  void signatureEnabled_customDuration_producesBean() {
    runner
        .withPropertyValues(
            "sap.security.cache.signature.enabled=true",
            "sap.security.cache.signature.duration=PT2M",
            "sap.security.cache.signature.ikm-env-var=STUBBED_IKM")
        .run(ctx -> assertThat(ctx).hasSingleBean(SignatureValidationCache.class));
  }

  @Test
  void signatureEnabled_invalidDuration_failsFast() {
    runner
        .withPropertyValues(
            "sap.security.cache.signature.enabled=true",
            "sap.security.cache.signature.duration=not-a-duration",
            "sap.security.cache.signature.ikm-env-var=STUBBED_IKM")
        .run(
            ctx -> {
              assertThat(ctx).hasFailed();
              assertThat(ctx.getStartupFailure())
                  .hasStackTraceContaining("Invalid ISO-8601 duration");
            });
  }

  @Test
  void userSuppliedTokenDecodeBean_isPreferred() {
    TokenDecodeCache user =
        new TokenDecodeCache(
            new NoopCache(),
            com.sap.cloud.security.token.cache.TokenDecodeCacheConfiguration.enabled(
                Duration.ofMinutes(1)));
    runner
        .withPropertyValues("sap.security.cache.token-decode.enabled=true")
        .withBean(TokenDecodeCache.class, () -> user)
        .run(ctx -> assertThat(ctx.getBean(TokenDecodeCache.class)).isSameAs(user));
  }

  @Test
  void defaultEnvVarReader_isRegisteredWhenNoUserOverride() {
    new ApplicationContextRunner()
        .withConfiguration(
            AutoConfigurations.of(TokenValidationCachesAutoConfiguration.class))
        .run(
            ctx ->
                assertThat(ctx.getBean(TokenValidationCachesAutoConfiguration.EnvVarReader.class))
                    .isNotNull());
  }

  @Configuration
  static class SharedCacheConfig {
    @Bean
    public SecurityCache<String, String> securityCache() {
      return new NoopCache();
    }
  }

  @Configuration
  static class EnvVarStubConfig {
    @Bean
    public TokenValidationCachesAutoConfiguration.EnvVarReader stubEnvVarReader() {
      return name -> "STUBBED_IKM".equals(name) ? "some-secret-value" : null;
    }
  }

  private static final class NoopCache implements SecurityCache<String, String> {
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
