/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache.caffeine;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.config.CacheConfiguration;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class CaffeineSecurityCacheTest {

  @Test
  void getReturnsEmptyForMissingKey() {
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMinutes(1));
    assertThat(cache.get("missing")).isEmpty();
  }

  @Test
  void setThenGetReturnsValue() {
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMinutes(1));
    cache.set("k", "v", Duration.ofSeconds(30));
    assertThat(cache.get("k")).contains("v");
  }

  @Test
  void deleteRemovesEntry() {
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMinutes(1));
    cache.set("k", "v", null);
    cache.delete("k");
    assertThat(cache.get("k")).isEmpty();
  }

  @Test
  void clearRemovesAllEntries() {
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMinutes(1));
    cache.set("k1", "v1", null);
    cache.set("k2", "v2", null);
    cache.clear();
    assertThat(cache.get("k1")).isEmpty();
    assertThat(cache.get("k2")).isEmpty();
  }

  @Test
  void perEntryTtlIsHonored() {
    ManualTicker ticker = new ManualTicker();
    // Cache-wide default is 1 hour, but the per-entry TTL of 30s must win.
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofHours(1), ticker);
    cache.set("k", "v", Duration.ofSeconds(30));
    assertThat(cache.get("k")).contains("v");
    ticker.advance(Duration.ofSeconds(31));
    assertThat(cache.get("k")).isEmpty();
  }

  @Test
  void perEntryTtlOverridesCacheWideDefault() {
    ManualTicker ticker = new ManualTicker();
    // 1ms cache-wide default, but the per-entry TTL of 1 day must win.
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMillis(1), ticker);
    cache.set("k", "v", Duration.ofDays(1));
    ticker.advance(Duration.ofMillis(50));
    assertThat(cache.get("k")).contains("v");
  }

  @Test
  void nullTtlUsesCacheWideDefault() {
    ManualTicker ticker = new ManualTicker();
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofHours(1), ticker);
    cache.set("k", "v", null);
    ticker.advance(Duration.ofMinutes(59));
    assertThat(cache.get("k")).contains("v");
    ticker.advance(Duration.ofMinutes(2));
    assertThat(cache.get("k")).isEmpty();
  }

  @Test
  void perEntryTtlsAreIndependentPerKey() {
    ManualTicker ticker = new ManualTicker();
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofHours(1), ticker);
    cache.set("short", "v", Duration.ofSeconds(30));
    cache.set("long", "v", Duration.ofHours(1));
    ticker.advance(Duration.ofSeconds(31));
    assertThat(cache.get("short")).isEmpty();
    assertThat(cache.get("long")).contains("v");
  }

  @Test
  void putReplacesEntryWithFreshTtl() {
    ManualTicker ticker = new ManualTicker();
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofHours(1), ticker);
    // A short-lived (negative) entry is replaced by a long-lived one; the replacement must
    // get a fresh expiration instead of inheriting the short one.
    cache.set("k", "negative", Duration.ofSeconds(30));
    ticker.advance(Duration.ofSeconds(10));
    cache.set("k", "positive", Duration.ofHours(1));
    ticker.advance(Duration.ofSeconds(45));
    assertThat(cache.get("k")).contains("positive");
  }

  @Test
  void valueWithoutTtlPrefixIsReturnedRawAndExpiresWithDefault() {
    ManualTicker ticker = new ManualTicker();
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofHours(1), ticker);
    // Simulate an entry written without the internal prefix (e.g. directly into the cache).
    cache.unwrap().put("k", "raw-value");
    assertThat(cache.get("k")).contains("raw-value");
    ticker.advance(Duration.ofHours(2));
    assertThat(cache.get("k")).isEmpty();
  }

  @Test
  void valueContainingDelimiterButNoTtlPrefixIsReturnedRaw() {
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMinutes(1));
    String value = "{\"keys\":[\"\u0000\"]}";
    cache.set("k", value, Duration.ofSeconds(30));
    assertThat(cache.get("k")).contains(value);
  }

  @Test
  void unwrapReturnsUnderlyingCaffeineCache() {
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMinutes(1));
    assertThat(cache.unwrap()).isNotNull();
    cache.set("k", "v", null);
    assertThat(cache.unwrap().getIfPresent("k")).isEqualTo("v");
  }

  @Test
  void preBuiltConstructor_wrapsExistingCache() {
    @SuppressWarnings("unchecked")
    Cache<String, String> delegate = mock(Cache.class);
    when(delegate.getIfPresent("k")).thenReturn("v");
    CaffeineSecurityCache cache = new CaffeineSecurityCache(delegate);
    assertThat(cache.get("k")).contains("v");
    assertThat(cache.unwrap()).isSameAs(delegate);
  }

  @Test
  void forConfiguration_readsSizeAndDuration() {
    CacheConfiguration cfg =
        new CacheConfiguration() {
          @Override
          public Duration getCacheDuration() {
            return Duration.ofMinutes(2);
          }

          @Override
          public int getCacheSize() {
            return 100;
          }

          @Override
          public boolean isCacheStatisticsEnabled() {
            return false;
          }
        };
    CaffeineSecurityCache cache = CaffeineSecurityCache.forConfiguration(cfg);
    assertThat(cache).isNotNull();
    cache.set("k", "v", null);
    assertThat(cache.get("k")).contains("v");
  }

  @Test
  void get_swallowsRuntimeExceptionAndReturnsEmpty() {
    @SuppressWarnings("unchecked")
    Cache<String, String> delegate = mock(Cache.class);
    when(delegate.getIfPresent(any())).thenThrow(new RuntimeException("boom"));
    CaffeineSecurityCache cache = new CaffeineSecurityCache(delegate);
    assertThat(cache.get("k")).isEmpty();
  }

  @Test
  void set_swallowsRuntimeException() {
    @SuppressWarnings("unchecked")
    Cache<String, String> delegate = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(delegate).put(eq("k"), anyString());
    CaffeineSecurityCache cache = new CaffeineSecurityCache(delegate);
    assertThatCode(() -> cache.set("k", "v", null)).doesNotThrowAnyException();
    assertThatCode(() -> cache.set("k", "v", Duration.ofSeconds(1)))
        .doesNotThrowAnyException();
  }

  @Test
  void delete_swallowsRuntimeException() {
    @SuppressWarnings("unchecked")
    Cache<String, String> delegate = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(delegate).invalidate(any());
    CaffeineSecurityCache cache = new CaffeineSecurityCache(delegate);
    assertThatCode(() -> cache.delete("k")).doesNotThrowAnyException();
  }

  @Test
  void clear_swallowsRuntimeException() {
    @SuppressWarnings("unchecked")
    Cache<String, String> delegate = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(delegate).invalidateAll();
    CaffeineSecurityCache cache = new CaffeineSecurityCache(delegate);
    assertThatCode(cache::clear).doesNotThrowAnyException();
  }

  /** Deterministic time source for expiration tests. */
  private static final class ManualTicker implements Ticker {
    private final AtomicLong nanos = new AtomicLong(0);

    @Override
    public long read() {
      return nanos.get();
    }

    void advance(final Duration duration) {
      nanos.addAndGet(duration.toNanos());
    }
  }
}
