/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.sap.cloud.security.cache.NoOpSecurityCache;
import com.sap.cloud.security.cache.SecurityCache;
import jakarta.annotation.Nonnull;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class SignatureValidationCacheTest {

  private static final byte[] IKM = "clientId:clientSecret".getBytes();
  private static final String TOKEN = "the-jwt-token-value";
  private static final String KID = "key-id-0";

  @Test
  void disabled_isKnownValidAlwaysFalse() {
    SignatureValidationCache cache =
        new SignatureValidationCache(
            new NoOpSecurityCache<>(), SignatureValidationCacheConfiguration.disabled());
    cache.recordValid(TOKEN, KID);
    assertThat(cache.isKnownValid(TOKEN, KID)).isFalse();
  }

  @Test
  void recordThenIsKnownValid_hits() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));

    cache.recordValid(TOKEN, KID);
    assertThat(cache.isKnownValid(TOKEN, KID)).isTrue();
  }

  @Test
  void differentToken_isMiss() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));

    cache.recordValid(TOKEN, KID);
    assertThat(cache.isKnownValid("other-token", KID)).isFalse();
  }

  @Test
  void differentKid_isMiss() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));

    cache.recordValid(TOKEN, KID);
    assertThat(cache.isKnownValid(TOKEN, "other-kid")).isFalse();
  }

  @Test
  void differentIkm_tamperedEntry_isDetectedAsMiss() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache writer =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));

    writer.recordValid(TOKEN, KID);

    // A different application (different IKM) would derive a different HMAC key — cached entry
    // from the wrong writer must fail verification.
    SignatureValidationCache reader =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(
                Duration.ofMinutes(5), "other-app-ikm".getBytes()));
    assertThat(reader.isKnownValid(TOKEN, KID)).isFalse();
  }

  @Test
  void tamperedValue_bitFlip_isDetectedAsMiss() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));

    cache.recordValid(TOKEN, KID);
    // Corrupt the stored value.
    String onlyKey = backing.store.keySet().iterator().next();
    String v = backing.store.get(onlyKey);
    backing.store.put(onlyKey, v.substring(0, v.length() - 1) + (v.charAt(v.length() - 1) == 'A' ? 'B' : 'A'));

    assertThat(cache.isKnownValid(TOKEN, KID)).isFalse();
  }

  @Test
  void cacheErrors_areSwallowed() {
    SignatureValidationCache cache =
        new SignatureValidationCache(
            new ThrowingCache(),
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));
    assertThatCode(
            () -> {
              cache.recordValid(TOKEN, KID);
              boolean known = cache.isKnownValid(TOKEN, KID);
              assertThat(known).isFalse();
            })
        .doesNotThrowAnyException();
  }

  @Test
  void unformattedEntry_isDetectedAsMiss() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));
    // Inject a raw entry that does not start with the OK| prefix.
    String key = com.sap.cloud.security.cache.CacheKeys.build(
        com.sap.cloud.security.cache.CacheKeys.NAMESPACE_SIG, TOKEN + "|" + KID);
    backing.store.put(key, "GARBAGE-not-OK-prefix");
    assertThat(cache.isKnownValid(TOKEN, KID)).isFalse();
  }

  @Test
  void invalidBase64Entry_isDetectedAsMiss() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));
    String key = com.sap.cloud.security.cache.CacheKeys.build(
        com.sap.cloud.security.cache.CacheKeys.NAMESPACE_SIG, TOKEN + "|" + KID);
    backing.store.put(key, "OK|not-valid-base64!!!!");
    assertThat(cache.isKnownValid(TOKEN, KID)).isFalse();
  }

  @Test
  void nullKid_treatedAsEmptyString() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing,
            SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(5), IKM));

    cache.recordValid(TOKEN, null);
    assertThat(cache.isKnownValid(TOKEN, null)).isTrue();
    // Empty string kid must produce the same key as null.
    assertThat(cache.isKnownValid(TOKEN, "")).isTrue();
  }

  @Test
  void recordValid_disabled_isNoOp() {
    MemoryCache backing = new MemoryCache();
    SignatureValidationCache cache =
        new SignatureValidationCache(
            backing, SignatureValidationCacheConfiguration.disabled());
    cache.recordValid(TOKEN, KID);
    assertThat(backing.store).isEmpty();
  }

  private static class MemoryCache implements SecurityCache<String, String> {
    final Map<String, String> store = new HashMap<>();

    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      return Optional.ofNullable(store.get(key));
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      store.put(key, value);
    }

    @Override
    public void delete(@Nonnull String key) {
      store.remove(key);
    }

    @Override
    public void clear() {
      store.clear();
    }
  }

  private static class ThrowingCache implements SecurityCache<String, String> {
    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      throw new RuntimeException("boom");
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      throw new RuntimeException("boom");
    }

    @Override
    public void delete(@Nonnull String key) {
      throw new RuntimeException("boom");
    }

    @Override
    public void clear() {
      throw new RuntimeException("boom");
    }
  }
}
