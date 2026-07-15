/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.cache;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.NoOpSecurityCache;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.util.HmacUtil;
import jakarta.annotation.Nonnull;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Opt-in cache that memoizes the (potentially expensive) result of JWT signature verification.
 *
 * <h2>Threat model</h2>
 *
 * Caching a boolean 'signature is valid' verdict shifts trust from the cryptographic verifier onto
 * the cache. If the cache is compromised or an attacker can inject entries, they can flip
 * previously-invalid tokens to 'valid'. This class defends against that by binding each cached
 * verdict to an <strong>HMAC-SHA256</strong> tag whose key is derived from the caller's own
 * credentials via HKDF-SHA256 (RFC 5869). Reading a tampered entry costs one HMAC comparison; the
 * verdict is then discarded and treated as a cache miss (with a WARN log).
 *
 * <p>The library never puts a <em>failed</em> validation into the cache. Only successful verdicts
 * are cached; failures always go back to the source of truth.
 *
 * <h2>Key and value</h2>
 *
 * <ul>
 *   <li>Key: {@link CacheKeys#build(String, String)} with namespace {@code sig} over {@code
 *       sha256(tokenString + "|" + kid)}. The token is not exposed as a key.
 *   <li>Value: {@code "OK|<base64(hmac)>"} — where {@code hmac} is {@code HMAC-SHA256(K,
 *       sha256(tokenString + "|" + kid))}, and {@code K} is the derived per-application HMAC key.
 * </ul>
 *
 * <h2>Enabling</h2>
 *
 * Off by default. Enable via {@link SignatureValidationCacheConfiguration#enabled(Duration,
 * byte[])}.
 *
 * @since 4.1.0
 */
public final class SignatureValidationCache {

  private static final Logger LOGGER = LoggerFactory.getLogger(SignatureValidationCache.class);
  private static final byte[] HKDF_INFO =
      "sap-security-sig-cache-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
  private static final String OK_PREFIX = "OK|";

  private final SecurityCache<String, String> cache;
  private final SignatureValidationCacheConfiguration configuration;
  private final byte[] hmacKey;

  public SignatureValidationCache(
      @Nonnull final SecurityCache<String, String> cache,
      @Nonnull final SignatureValidationCacheConfiguration configuration) {
    this.cache = configuration.isCacheDisabled() ? new NoOpSecurityCache<>() : cache;
    this.configuration = configuration;
    this.hmacKey =
        configuration.isCacheDisabled()
            ? new byte[0]
            : HmacUtil.hkdfSha256(configuration.getIkm(), HKDF_INFO, 32);
  }

  /**
   * Look up a previously-cached 'valid' verdict for the given token / kid combination.
   *
   * @param tokenValue the raw JWT string
   * @param kid the key id header of the JWT (may be null / empty; treated as literal empty string)
   * @return {@code true} if we have a fresh, cryptographically-verified 'OK' entry; {@code false}
   *     if there is no entry, if the entry is tampered, or on any cache error.
   */
  public boolean isKnownValid(@Nonnull final String tokenValue, final String kid) {
    if (configuration.isCacheDisabled()) {
      return false;
    }
    final String fingerprint = tokenValue + "|" + (kid == null ? "" : kid);
    final String cacheKey = CacheKeys.build(CacheKeys.NAMESPACE_SIG, fingerprint);
    Optional<String> raw = safeGet(cacheKey);
    if (raw.isEmpty()) {
      return false;
    }
    return verifyMac(fingerprint, raw.get());
  }

  /**
   * Record a 'valid' verdict for the given token / kid combination. Only call this AFTER the full
   * cryptographic RSA verification has succeeded.
   */
  public void recordValid(@Nonnull final String tokenValue, final String kid) {
    if (configuration.isCacheDisabled()) {
      return;
    }
    final String fingerprint = tokenValue + "|" + (kid == null ? "" : kid);
    final String cacheKey = CacheKeys.build(CacheKeys.NAMESPACE_SIG, fingerprint);
    final byte[] mac = HmacUtil.hmacSha256(hmacKey, HmacUtil.utf8(fingerprint));
    final String value = OK_PREFIX + Base64.getEncoder().encodeToString(mac);
    safeSet(cacheKey, value, configuration.getCacheDuration());
  }

  private boolean verifyMac(final String fingerprint, final String cachedValue) {
    if (cachedValue == null || !cachedValue.startsWith(OK_PREFIX)) {
      LOGGER.warn("Cached signature entry has unexpected format — treating as miss");
      return false;
    }
    final byte[] cachedMac;
    try {
      cachedMac = Base64.getDecoder().decode(cachedValue.substring(OK_PREFIX.length()));
    } catch (final IllegalArgumentException e) {
      LOGGER.warn("Cached signature entry is not valid Base64 — treating as miss");
      return false;
    }
    final byte[] expected = HmacUtil.hmacSha256(hmacKey, HmacUtil.utf8(fingerprint));
    boolean ok = HmacUtil.verify(cachedMac, expected);
    if (!ok) {
      LOGGER.warn("Cached signature entry failed HMAC verification — treating as miss");
    }
    return ok;
  }

  private Optional<String> safeGet(final String cacheKey) {
    try {
      return cache.get(cacheKey);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.get failed for signature entry: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private void safeSet(final String cacheKey, final String value, final Duration ttl) {
    try {
      cache.set(cacheKey, value, ttl);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.set failed for signature entry: {}", e.getMessage());
    }
  }
}
