/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import static java.time.ZoneOffset.UTC;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import jakarta.annotation.Nonnull;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Tests specific to the {@link com.sap.cloud.security.cache.SecurityCache} integration. */
class AbstractOAuth2TokenServiceSecurityCacheTest {

  private static final URI URI_TOKEN =
      URI.create("http://test.token.endpoint/oauth/token");
  private static final Instant NOW =
      LocalDateTime.of(2020, 1, 1, 0, 0, 0, 0).toInstant(UTC);
  private static final ClientIdentity CLIENT = new ClientCredentials("clientId", "clientSecret");

  @Test
  void cacheHit_deserializedResponseMatchesOriginal() throws OAuth2ServiceException {
    RecordingCache cache = new RecordingCache();
    SingleFlightService svc =
        new SingleFlightService(TokenCacheConfiguration.defaultConfiguration(), cache);

    OAuth2TokenResponse first =
        svc.retrieveAccessTokenViaClientCredentialsGrant(URI_TOKEN, CLIENT, null, null, null, false);
    OAuth2TokenResponse second =
        svc.retrieveAccessTokenViaClientCredentialsGrant(URI_TOKEN, CLIENT, null, null, null, false);

    assertThat(second.getAccessToken()).isEqualTo(first.getAccessToken());
    assertThat(second.getRefreshToken()).isEqualTo(first.getRefreshToken());
    assertThat(second.getTokenType()).isEqualTo(first.getTokenType());
    assertThat(second.getExpiredAt()).isEqualTo(first.getExpiredAt());
    assertThat(svc.calls.get()).isEqualTo(1);
    // The cache saw one write and two reads.
    assertThat(cache.setCount.get()).isEqualTo(1);
    assertThat(cache.getCount.get()).isEqualTo(2);
  }

  @Test
  void cacheErrors_areSwallowed_serviceKeepsWorking() throws OAuth2ServiceException {
    ThrowingCache cache = new ThrowingCache();
    SingleFlightService svc =
        new SingleFlightService(TokenCacheConfiguration.defaultConfiguration(), cache);

    // The cache throws on every op; the service must fall through to the underlying fetch.
    // Because the ThrowingCache never returns hits, the fetch is invoked on every call.
    assertThatCode(
            () -> {
              svc.retrieveAccessTokenViaClientCredentialsGrant(
                  URI_TOKEN, CLIENT, null, null, null, false);
              svc.retrieveAccessTokenViaClientCredentialsGrant(
                  URI_TOKEN, CLIENT, null, null, null, false);
            })
        .doesNotThrowAnyException();
    // No cache-hit — the fetcher is invoked every time.
    assertThat(svc.calls.get()).isEqualTo(2);
  }

  @Test
  void singleFlight_twoConcurrentMisses_produceOneHttpCall() throws Exception {
    SlowFetchService svc =
        new SlowFetchService(TokenCacheConfiguration.defaultConfiguration());
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      CountDownLatch started = new CountDownLatch(2);
      CountDownLatch bothStarted = new CountDownLatch(1);
      svc.beforeFetch = started;
      svc.releaseFetch = bothStarted;

      Future<OAuth2TokenResponse> f1 =
          pool.submit(
              () ->
                  svc.retrieveAccessTokenViaClientCredentialsGrant(
                      URI_TOKEN, CLIENT, null, null, null, false));
      Future<OAuth2TokenResponse> f2 =
          pool.submit(
              () ->
                  svc.retrieveAccessTokenViaClientCredentialsGrant(
                      URI_TOKEN, CLIENT, null, null, null, false));

      // Wait until both threads have entered getOrRequestAccessToken and one has become the
      // fetcher (the other should be waiting on the CF).
      Thread.sleep(150);
      bothStarted.countDown();

      OAuth2TokenResponse r1 = f1.get(5, TimeUnit.SECONDS);
      OAuth2TokenResponse r2 = f2.get(5, TimeUnit.SECONDS);

      assertThat(r1.getAccessToken()).isEqualTo(r2.getAccessToken());
      // The whole point of single-flight: two callers, one fetch.
      assertThat(svc.calls.get()).isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void singleFlight_threeConcurrentMisses_writeCacheOnce() throws Exception {
    RecordingCache cache = new RecordingCache();
    SlowFetchService svc =
        new SlowFetchService(TokenCacheConfiguration.defaultConfiguration(), cache);
    ExecutorService pool = Executors.newFixedThreadPool(3);
    try {
      CountDownLatch bothStarted = new CountDownLatch(1);
      svc.releaseFetch = bothStarted;

      Future<OAuth2TokenResponse> f1 =
          pool.submit(
              () ->
                  svc.retrieveAccessTokenViaClientCredentialsGrant(
                      URI_TOKEN, CLIENT, null, null, null, false));
      Future<OAuth2TokenResponse> f2 =
          pool.submit(
              () ->
                  svc.retrieveAccessTokenViaClientCredentialsGrant(
                      URI_TOKEN, CLIENT, null, null, null, false));
      Future<OAuth2TokenResponse> f3 =
          pool.submit(
              () ->
                  svc.retrieveAccessTokenViaClientCredentialsGrant(
                      URI_TOKEN, CLIENT, null, null, null, false));

      Thread.sleep(200);
      bothStarted.countDown();

      f1.get(5, TimeUnit.SECONDS);
      f2.get(5, TimeUnit.SECONDS);
      f3.get(5, TimeUnit.SECONDS);

      // One fetch, one cache write — no matter how many waiters there are.
      assertThat(svc.calls.get()).isEqualTo(1);
      assertThat(cache.setCount.get()).isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void singleFlight_fetcherFails_waitersSeeSameException() throws Exception {
    FailingFetchService svc =
        new FailingFetchService(TokenCacheConfiguration.defaultConfiguration());
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      CountDownLatch release = new CountDownLatch(1);
      svc.release = release;

      Future<OAuth2TokenResponse> f1 =
          pool.submit(
              () ->
                  svc.retrieveAccessTokenViaClientCredentialsGrant(
                      URI_TOKEN, CLIENT, null, null, null, false));
      Future<OAuth2TokenResponse> f2 =
          pool.submit(
              () ->
                  svc.retrieveAccessTokenViaClientCredentialsGrant(
                      URI_TOKEN, CLIENT, null, null, null, false));

      Thread.sleep(150);
      release.countDown();

      assertThat(catchThrowable(f1)).hasRootCauseMessage("fetch failed");
      assertThat(catchThrowable(f2)).hasRootCauseMessage("fetch failed");
    } finally {
      pool.shutdownNow();
    }
  }

  private static Throwable catchThrowable(Future<?> f) {
    try {
      f.get(5, TimeUnit.SECONDS);
      return null;
    } catch (Exception e) {
      return e;
    }
  }

  // --- test doubles ---

  private static final class SingleFlightService extends AbstractOAuth2TokenService {
    final AtomicInteger calls = new AtomicInteger();

    SingleFlightService(
        TokenCacheConfiguration cfg, SecurityCache<String, String> cache) {
      super(cfg, cache);
    }

    @Override
    protected OAuth2TokenResponse requestAccessToken(
        URI tokenEndpointUri, HttpHeaders headers, Map<String, String> parameters) {
      calls.incrementAndGet();
      return new OAuth2TokenResponse(
          "access-" + calls.get(),
          null,
          "bearer",
          Instant.now().plus(Duration.ofDays(1)).toEpochMilli());
    }
  }

  private static final class SlowFetchService extends AbstractOAuth2TokenService {
    final AtomicInteger calls = new AtomicInteger();
    volatile CountDownLatch beforeFetch;
    volatile CountDownLatch releaseFetch;

    SlowFetchService(TokenCacheConfiguration cfg) {
      super(cfg);
    }

    SlowFetchService(TokenCacheConfiguration cfg, SecurityCache<String, String> cache) {
      super(cfg, cache);
    }

    @Override
    protected OAuth2TokenResponse requestAccessToken(
        URI tokenEndpointUri, HttpHeaders headers, Map<String, String> parameters) {
      calls.incrementAndGet();
      try {
        if (beforeFetch != null) {
          beforeFetch.countDown();
        }
        if (releaseFetch != null) {
          releaseFetch.await(3, TimeUnit.SECONDS);
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      return new OAuth2TokenResponse(
          "access", null, "bearer", Instant.now().plus(Duration.ofHours(1)).toEpochMilli());
    }
  }

  private static final class FailingFetchService extends AbstractOAuth2TokenService {
    volatile CountDownLatch release;

    FailingFetchService(TokenCacheConfiguration cfg) {
      super(cfg);
    }

    @Override
    protected OAuth2TokenResponse requestAccessToken(
        URI tokenEndpointUri, HttpHeaders headers, Map<String, String> parameters)
        throws OAuth2ServiceException {
      try {
        if (release != null) {
          release.await(3, TimeUnit.SECONDS);
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      throw new OAuth2ServiceException("fetch failed");
    }
  }

  private static class RecordingCache implements SecurityCache<String, String> {
    final AtomicInteger getCount = new AtomicInteger();
    final AtomicInteger setCount = new AtomicInteger();
    private volatile String storedKey;
    private volatile String storedValue;

    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      getCount.incrementAndGet();
      if (key.equals(storedKey)) {
        return Optional.ofNullable(storedValue);
      }
      return Optional.empty();
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      setCount.incrementAndGet();
      storedKey = key;
      storedValue = value;
    }

    @Override
    public void delete(@Nonnull String key) {
      if (key.equals(storedKey)) {
        storedKey = null;
        storedValue = null;
      }
    }

    @Override
    public void clear() {
      storedKey = null;
      storedValue = null;
    }
  }

  private static class ThrowingCache implements SecurityCache<String, String> {
    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
      throw new RuntimeException("cache down");
    }

    @Override
    public void set(@Nonnull String key, @Nonnull String value, Duration ttl) {
      throw new RuntimeException("cache down");
    }

    @Override
    public void delete(@Nonnull String key) {
      throw new RuntimeException("cache down");
    }

    @Override
    public void clear() {
      throw new RuntimeException("cache down");
    }
  }
}
