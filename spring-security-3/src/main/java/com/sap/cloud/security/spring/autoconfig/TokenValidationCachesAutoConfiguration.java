/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.autoconfig;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.cache.caffeine.CaffeineSecurityCache;
import com.sap.cloud.security.token.cache.SignatureValidationCache;
import com.sap.cloud.security.token.cache.SignatureValidationCacheConfiguration;
import com.sap.cloud.security.token.cache.TokenDecodeCache;
import com.sap.cloud.security.token.cache.TokenDecodeCacheConfiguration;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * Optional auto-configuration for the opt-in token decode cache ({@link TokenDecodeCache}) and the
 * opt-in signature validation cache ({@link SignatureValidationCache}). Off by default.
 *
 * <h2>Token decode cache</h2>
 *
 * Enable via {@code sap.security.cache.token-decode.enabled=true}. TTL cap is
 * {@code sap.security.cache.token-decode.duration} (ISO-8601 duration; default {@code PT5M}).
 *
 * <h2>Signature validation cache</h2>
 *
 * Enable via {@code sap.security.cache.signature.enabled=true}. TTL cap is
 * {@code sap.security.cache.signature.duration} (default {@code PT5M}). The HMAC input keying
 * material must be supplied via an environment variable whose <em>name</em> is configured through
 * {@code sap.security.cache.signature.ikm-env-var}. The raw bytes never appear in {@code
 * application.yml}, which keeps them out of configuration repositories.
 *
 * <p>The signature cache bean is exposed for injection but is NOT wired into the JwtSignatureValidator
 * automatically — the caller must opt-in explicitly to avoid surprising security implications.
 *
 * @since 4.1.0
 */
@Configuration
@AutoConfigureAfter(SecurityCacheAutoConfiguration.class)
public class TokenValidationCachesAutoConfiguration {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(TokenValidationCachesAutoConfiguration.class);

  static final String TOKEN_DECODE_ENABLED = "sap.security.cache.token-decode.enabled";
  static final String TOKEN_DECODE_DURATION = "sap.security.cache.token-decode.duration";
  static final String SIGNATURE_ENABLED = "sap.security.cache.signature.enabled";
  static final String SIGNATURE_DURATION = "sap.security.cache.signature.duration";
  static final String SIGNATURE_IKM_ENV_VAR = "sap.security.cache.signature.ikm-env-var";

  /**
   * Marker type for a {@code Function<String,String>} bean that resolves environment-variable names
   * to their values. The default reads {@link System#getenv(String)}; tests may substitute their
   * own to keep the JVM's real environment out of the picture.
   *
   * @since 4.1.0
   */
  @FunctionalInterface
  public interface EnvVarReader extends Function<String, String> {}

  @Bean
  @ConditionalOnMissingBean(EnvVarReader.class)
  public EnvVarReader defaultEnvVarReader() {
    return System::getenv;
  }

  @Bean
  @ConditionalOnProperty(prefix = "sap.security.cache.token-decode", name = "enabled", havingValue = "true")
  @ConditionalOnMissingBean(TokenDecodeCache.class)
  public TokenDecodeCache tokenDecodeCache(
      final Environment env,
      final ObjectProvider<SecurityCache<String, String>> sharedCache) {
    Duration ttl = readDuration(env, TOKEN_DECODE_DURATION, Duration.ofMinutes(5));
    SecurityCache<String, String> cache = sharedCache.getIfAvailable();
    if (cache == null) {
      cache = new CaffeineSecurityCache(10_000, ttl);
      LOGGER.info(
          "No shared SecurityCache bean available — falling back to in-memory Caffeine for {}",
          CacheKeys.NAMESPACE_DECODE);
    }
    return new TokenDecodeCache(cache, TokenDecodeCacheConfiguration.enabled(ttl));
  }

  @Bean
  @ConditionalOnProperty(prefix = "sap.security.cache.signature", name = "enabled", havingValue = "true")
  @ConditionalOnMissingBean(SignatureValidationCache.class)
  public SignatureValidationCache signatureValidationCache(
      final Environment env,
      final ObjectProvider<SecurityCache<String, String>> sharedCache,
      final EnvVarReader envVarReader) {
    String envVar = env.getProperty(SIGNATURE_IKM_ENV_VAR);
    if (envVar == null || envVar.isBlank()) {
      throw new IllegalStateException(
          SIGNATURE_ENABLED + "=true but " + SIGNATURE_IKM_ENV_VAR + " is not set. Configure the"
              + " NAME of an environment variable that supplies the HMAC input keying material"
              + " (per-application secret). The raw bytes must never be committed to configuration.");
    }
    String ikmValue = envVarReader.apply(envVar);
    if (ikmValue == null || ikmValue.isEmpty()) {
      throw new IllegalStateException(
          SIGNATURE_ENABLED + "=true and " + SIGNATURE_IKM_ENV_VAR + "='" + envVar + "', but the"
              + " referenced environment variable is not set or is empty.");
    }
    Duration ttl = readDuration(env, SIGNATURE_DURATION, Duration.ofMinutes(5));
    byte[] ikm = ikmValue.getBytes(StandardCharsets.UTF_8);
    SecurityCache<String, String> cache = sharedCache.getIfAvailable();
    if (cache == null) {
      cache = new CaffeineSecurityCache(10_000, ttl);
      LOGGER.info(
          "No shared SecurityCache bean available — falling back to in-memory Caffeine for {}",
          CacheKeys.NAMESPACE_SIG);
    }
    return new SignatureValidationCache(cache, SignatureValidationCacheConfiguration.enabled(ttl, ikm));
  }

  private static Duration readDuration(
      final Environment env, final String property, final Duration fallback) {
    String raw = env.getProperty(property);
    if (raw == null || raw.isBlank()) {
      return fallback;
    }
    try {
      return Duration.parse(raw);
    } catch (final java.time.format.DateTimeParseException e) {
      throw new IllegalStateException(
          "Invalid ISO-8601 duration for " + property + ": " + raw, e);
    }
  }
}
