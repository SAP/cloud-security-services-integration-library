/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sap.cloud.security.cache.NoOpSecurityCache;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.token.Token;
import jakarta.annotation.Nonnull;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class TokenDecodeCacheTest {

  private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

  private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

  @Test
  void disabledCache_alwaysDelegates() {
    TokenDecodeCache cache =
        new TokenDecodeCache(new NoOpSecurityCache<>(), TokenDecodeCacheConfiguration.disabled());
    AtomicInteger calls = new AtomicInteger();
    cache.getOrDecode("token-1", raw -> mockedTokenExpiringAt(NOW.plus(Duration.ofMinutes(10)), calls));
    cache.getOrDecode("token-1", raw -> mockedTokenExpiringAt(NOW.plus(Duration.ofMinutes(10)), calls));
    assertThat(calls.get()).isEqualTo(2);
  }

  @Test
  void enabledCache_secondCallHits() {
    RecordingCache backing = new RecordingCache();
    TokenDecodeCache cache =
        new TokenDecodeCache(
            backing,
            TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(5)),
            clock);
    AtomicInteger calls = new AtomicInteger();
    cache.getOrDecode(
        "token-1", raw -> mockedTokenExpiringAt(NOW.plus(Duration.ofMinutes(10)), calls));
    cache.getOrDecode(
        "token-1", raw -> mockedTokenExpiringAt(NOW.plus(Duration.ofMinutes(10)), calls));
    // Second call served from cache: only one decoder invocation on the primary path.
    // (There is a second decoder invocation on the cache-hit branch to rebuild the Token from
    // the cached value — that's expected.)
    assertThat(calls.get()).isEqualTo(2);
    assertThat(backing.setCount.get()).isEqualTo(1);
  }

  @Test
  void ttlIsCappedAtRemainingLifetime() {
    TokenDecodeCache cache =
        new TokenDecodeCache(
            new NoOpSecurityCache<>(),
            TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(5)),
            clock);
    Token token = mockedTokenExpiringAt(NOW.plus(Duration.ofSeconds(30)), new AtomicInteger());
    Duration ttl = cache.computeTtl(token);
    assertThat(ttl).isEqualTo(Duration.ofSeconds(30));
  }

  @Test
  void ttlIsCappedAtConfiguredMax() {
    TokenDecodeCache cache =
        new TokenDecodeCache(
            new NoOpSecurityCache<>(),
            TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(5)),
            clock);
    Token token = mockedTokenExpiringAt(NOW.plus(Duration.ofHours(1)), new AtomicInteger());
    Duration ttl = cache.computeTtl(token);
    assertThat(ttl).isEqualTo(Duration.ofMinutes(5));
  }

  @Test
  void expiredTokensAreNotCached() {
    RecordingCache backing = new RecordingCache();
    TokenDecodeCache cache =
        new TokenDecodeCache(
            backing,
            TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(5)),
            clock);
    AtomicInteger calls = new AtomicInteger();
    cache.getOrDecode(
        "token-1", raw -> mockedTokenExpiringAt(NOW.minus(Duration.ofSeconds(1)), calls));
    assertThat(backing.setCount.get()).isZero();
  }

  @Test
  void cacheErrors_areSwallowed() {
    TokenDecodeCache cache =
        new TokenDecodeCache(
            new ThrowingCache(),
            TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(5)),
            clock);
    AtomicInteger calls = new AtomicInteger();
    assertThatCode(
            () ->
                cache.getOrDecode(
                    "token-1",
                    raw -> mockedTokenExpiringAt(NOW.plus(Duration.ofMinutes(10)), calls)))
        .doesNotThrowAnyException();
  }

  private static Token mockedTokenExpiringAt(final Instant exp, final AtomicInteger counter) {
    counter.incrementAndGet();
    Token t = mock(Token.class);
    when(t.getExpiration()).thenReturn(exp);
    when(t.getTokenValue()).thenReturn("token-1");
    return t;
  }

  private static class RecordingCache implements SecurityCache<String, String> {
    final AtomicInteger setCount = new AtomicInteger();
    private final Map<String, String> store = new HashMap<>();

    @Nonnull
    @Override
    public Optional<String> get(@Nonnull String key) {
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
