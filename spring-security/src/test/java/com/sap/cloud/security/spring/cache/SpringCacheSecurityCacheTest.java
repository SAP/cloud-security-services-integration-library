/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.cache;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.cache.concurrent.ConcurrentMapCache;

class SpringCacheSecurityCacheTest {

  @Test
  void roundTrip() {
    ConcurrentMapCache springCache = new ConcurrentMapCache("test");
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(springCache);

    assertThat(cut.get("k")).isEmpty();
    cut.set("k", "v", Duration.ofMinutes(1));
    assertThat(cut.get("k")).contains("v");
    cut.delete("k");
    assertThat(cut.get("k")).isEmpty();
  }

  @Test
  void clearRemovesAll() {
    ConcurrentMapCache springCache = new ConcurrentMapCache("test");
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(springCache);

    cut.set("k1", "v1", null);
    cut.set("k2", "v2", null);
    cut.clear();
    assertThat(cut.get("k1")).isEmpty();
    assertThat(cut.get("k2")).isEmpty();
  }

  @Test
  void nonStringValueTreatedAsMiss() {
    ConcurrentMapCache springCache = new ConcurrentMapCache("test");
    springCache.put("k", 42); // put a non-String directly
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(springCache);

    assertThat(cut.get("k")).isEmpty();
  }
}
