/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
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

  @Test
  void singleFlight_twoConcurrentMisses_produceOneJwksCall() throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger fetchCount = new AtomicInteger();
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenAnswer(
            inv -> {
              fetchCount.incrementAndGet();
              release.await(5, TimeUnit.SECONDS);
              return jwksJson;
            });

    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(svc);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<PublicKey> f1 = pool.submit(() -> cut.getPublicKey(params, PARAMS));
      Future<PublicKey> f2 = pool.submit(() -> cut.getPublicKey(params, PARAMS));

      // Let both threads enter; the second one should wait on the in-flight future instead of
      // issuing its own HTTP call.
      Thread.sleep(150);
      release.countDown();

      PublicKey k1 = f1.get(10, TimeUnit.SECONDS);
      PublicKey k2 = f2.get(10, TimeUnit.SECONDS);

      assertThat(k2.getEncoded()).isEqualTo(k1.getEncoded());
      // The whole point of single-flight: two callers, one upstream JWKS fetch.
      assertThat(fetchCount.get()).isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void fetchFailure_isNegativelyCached_repeatedCallsFailFastWithoutNetwork() throws Exception {
    RecordingCache cache = new RecordingCache();
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenThrow(notFound());

    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);
    // The failure is now negatively cached: the second call must fail fast without a network call.
    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);

    verify(svc, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());
    // A negative entry (not the JWKS JSON) was written to the cache.
    String key = cacheKey();
    assertThat(cache.store.get(key)).isNotNull().isNotEqualTo(jwksJson);
  }

  @Test
  void negativeCache_expiresAfterTtl_nextCallRetries() throws Exception {
    RecordingCache cache = new RecordingCache();
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenThrow(notFound())
        .thenReturn(jwksJson);

    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);
    // Still within the negative TTL: fails fast, no second network call.
    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);
    verify(svc, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());

    // Advance past the negative TTL; the next call retries and succeeds.
    cache.advanceSeconds(31);
    assertThat(cut.getPublicKey(params, PARAMS)).isNotNull();
    verify(svc, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());
  }

  @Test
  void successfulFetch_afterNegativeEntry_cachesPositiveValue() throws Exception {
    RecordingCache cache = new RecordingCache();
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenThrow(notFound())
        .thenReturn(jwksJson);

    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);
    cache.advanceSeconds(31);
    cut.getPublicKey(params, PARAMS);

    // The negative entry must be replaced by the real JWKS JSON.
    assertThat(cache.store.get(cacheKey())).isEqualTo(jwksJson);
    // And the following call is served from the positive entry.
    cut.getPublicKey(params, PARAMS);
    verify(svc, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());
  }

  @Test
  void singleFlight_twoConcurrentFailures_produceOneJwksCallAndOneNegativeEntry()
      throws Exception {
    RecordingCache cache = new RecordingCache();
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger fetchCount = new AtomicInteger();
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenAnswer(
            inv -> {
              fetchCount.incrementAndGet();
              release.await(5, TimeUnit.SECONDS);
              throw notFound();
            });

    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<PublicKey> f1 = pool.submit(() -> cut.getPublicKey(params, PARAMS));
      Future<PublicKey> f2 = pool.submit(() -> cut.getPublicKey(params, PARAMS));

      Thread.sleep(150);
      release.countDown();

      assertThatThrownBy(() -> f1.get(10, TimeUnit.SECONDS))
          .isInstanceOf(ExecutionException.class)
          .hasCauseInstanceOf(OAuth2ServiceException.class);
      assertThatThrownBy(() -> f2.get(10, TimeUnit.SECONDS))
          .isInstanceOf(ExecutionException.class)
          .hasCauseInstanceOf(OAuth2ServiceException.class);

      // Two concurrent callers, one upstream call and exactly one negative cache write.
      assertThat(fetchCount.get()).isEqualTo(1);
      assertThat(cache.setCount.get()).isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void serverError_isNotNegativelyCached_nextCallRetries() throws Exception {
    RecordingCache cache = new RecordingCache();
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenThrow(serverError());

    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);
    // Transient failures are not negatively cached: the second call must reach the network
    // again instead of failing fast on a negative entry.
    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);

    verify(svc, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());
    assertThat(cache.setCount.get()).isZero();
    assertThat(cache.store).isEmpty();
  }

  @Test
  void transportError_isNotNegativelyCached_nextCallRetries() throws Exception {
    RecordingCache cache = new RecordingCache();
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);
    // No HTTP status code (0) — e.g. a read timeout or a connection reset.
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenThrow(new OAuth2ServiceException("Read timed out"));

    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);
    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);

    verify(svc, times(2)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());
    assertThat(cache.setCount.get()).isZero();
    assertThat(cache.store).isEmpty();
  }

  @Test
  void rateLimit_isNegativelyCachedLikeOtherClientErrors() throws Exception {
    RecordingCache cache = new RecordingCache();
    OAuth2TokenKeyServiceWithCache cut =
        OAuth2TokenKeyServiceWithCache.getInstance()
            .withTokenKeyService(svc)
            .withSecurityCache(cache);
    when(svc.retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap()))
        .thenThrow(rateLimited());

    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);
    // 429 is a client error and is treated like any other stable 4xx: fail fast within the
    // negative TTL.
    assertThatThrownBy(() -> cut.getPublicKey(params, PARAMS))
        .isInstanceOf(OAuth2ServiceException.class);

    verify(svc, times(1)).retrieveTokenKeys(eq(TOKEN_KEYS_URI), anyMap());
    assertThat(cache.store.get(cacheKey()))
        .isEqualTo(OAuth2TokenKeyServiceWithCache.NEGATIVE_CACHE_MARKER);
  }

  private static OAuth2ServiceException notFound() {
    return OAuth2ServiceException.builder("Not Found")
        .withStatusCode(404)
        .withUri(TOKEN_KEYS_URI)
        .build();
  }

  private static OAuth2ServiceException serverError() {
    return OAuth2ServiceException.builder("Internal Server Error")
        .withStatusCode(500)
        .withUri(TOKEN_KEYS_URI)
        .build();
  }

  private static OAuth2ServiceException rateLimited() {
    return OAuth2ServiceException.builder("Too Many Requests")
        .withStatusCode(429)
        .withUri(TOKEN_KEYS_URI)
        .build();
  }

  private static String cacheKey() {
    return CacheKeys.build(
        CacheKeys.NAMESPACE_JWKS,
        new OAuth2TokenKeyServiceWithCache.CacheKey(TOKEN_KEYS_URI, PARAMS).toString());
  }

  private static class RecordingCache implements SecurityCache<String, String> {
    final AtomicInteger getCount = new AtomicInteger();
    final AtomicInteger setCount = new AtomicInteger();
    final Map<String, String> store = new HashMap<>();
    private final Map<String, Long> expiresAt = new HashMap<>();
    private final AtomicLong nowSeconds = new AtomicLong(0);

    void advanceSeconds(final long seconds) {
      nowSeconds.addAndGet(seconds);
    }

    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      getCount.incrementAndGet();
      synchronized (store) {
        Long exp = expiresAt.get(key);
        if (exp != null && nowSeconds.get() >= exp) {
          store.remove(key);
          expiresAt.remove(key);
        }
        return Optional.ofNullable(store.get(key));
      }
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      setCount.incrementAndGet();
      synchronized (store) {
        store.put(key, value);
        if (ttl != null) {
          expiresAt.put(key, nowSeconds.get() + ttl.toSeconds());
        } else {
          expiresAt.remove(key);
        }
      }
    }

    @Override
    public void delete(@Nonnull String key) {
      synchronized (store) {
        store.remove(key);
        expiresAt.remove(key);
      }
    }

    @Override
    public void clear() {
      synchronized (store) {
        store.clear();
        expiresAt.clear();
      }
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
