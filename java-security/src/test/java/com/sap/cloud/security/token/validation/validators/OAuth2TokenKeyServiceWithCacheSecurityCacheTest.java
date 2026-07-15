/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import jakarta.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OAuth2TokenKeyServiceWithCacheSecurityCacheTest {

  private static final URI TOKEN_KEYS_URI = URI.create("https://myauth.com/jwks_uri");
  private static final Map<String, String> PARAMS =
      Map.of(HttpHeaders.X_APP_TID, "tid", HttpHeaders.X_CLIENT_ID, "cid");
  private final OAuth2TokenKeyServiceWithCache.KeyParameters params =
      new OAuth2TokenKeyServiceWithCache.KeyParameters(
          JwtSignatureAlgorithm.RS256, "key-id-0", TOKEN_KEYS_URI);

  private OAuth2TokenKeyService svc;
  private String jwksJson;

  @BeforeEach
  void setup() throws IOException {
    svc = mock(OAuth2TokenKeyService.class);
    jwksJson = IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8);
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap())).thenReturn(jwksJson);
  }

  @Test
  void cacheGet_hitAvoidsUpstreamCall() throws Exception {
    RecordingCache cache = new RecordingCache();
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);

    cut.getPublicKey(params, PARAMS);
    cut.getPublicKey(params, PARAMS);

    verify(svc, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), eq(PARAMS));
    // One set + two gets.
    assertThat(cache.setCount.get()).isEqualTo(1);
    assertThat(cache.getCount.get()).isEqualTo(2);
  }

  @Test
  void cacheGet_publicKeyReconstructedFromCachedJson() throws Exception {
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(svc);

    PublicKey first = cut.getPublicKey(params, PARAMS);
    PublicKey second = cut.getPublicKey(params, PARAMS);
    assertThat(second.getEncoded()).isEqualTo(first.getEncoded());
  }

  @Test
  void cacheErrors_areSwallowed_serviceKeepsWorking() throws Exception {
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(new ThrowingCache());

    assertThatCode(
            () -> {
              cut.getPublicKey(params, PARAMS);
              cut.getPublicKey(params, PARAMS);
            })
        .doesNotThrowAnyException();
    // Cache never hits — every call refetches.
    verify(svc, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());
  }

  private static class RecordingCache implements SecurityCache<String, String> {
    final AtomicInteger getCount = new AtomicInteger();
    final AtomicInteger setCount = new AtomicInteger();
    private final Map<String, String> store = new HashMap<>();

    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      getCount.incrementAndGet();
      return Optional.ofNullable(store.get(key));
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      setCount.incrementAndGet();
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
