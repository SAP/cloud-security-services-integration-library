/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache.caffeine;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Optional;
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
  void perEntryTtlIsIgnoredInFavorOfCacheWideDuration() {
    // 10ms expire-after-write, per-entry ttl is 1 day; caffeine still evicts.
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMillis(1));
    cache.set("k", "v", Duration.ofDays(1));
    // Sleep to let expire-after-write kick in.
    try {
      Thread.sleep(50);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    Optional<String> value = cache.get("k");
    // The value should be gone (best effort — caffeine cleanup happens lazily).
    assertThat(value).isEmpty();
  }

  @Test
  void unwrapReturnsUnderlyingCaffeineCache() {
    CaffeineSecurityCache cache = new CaffeineSecurityCache(10, Duration.ofMinutes(1));
    assertThat(cache.unwrap()).isNotNull();
    cache.set("k", "v", null);
    assertThat(cache.unwrap().getIfPresent("k")).isEqualTo("v");
  }
}
