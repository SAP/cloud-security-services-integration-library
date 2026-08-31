/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.cache.Cache;
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

  @Test
  void get_swallowsExceptionAndReturnsEmpty() {
    Cache broken = mock(Cache.class);
    when(broken.get(any())).thenThrow(new RuntimeException("boom"));
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(broken);
    assertThat(cut.get("k")).isEmpty();
  }

  @Test
  void set_swallowsException() {
    Cache broken = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(broken).put(any(), any());
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(broken);
    assertThatCode(() -> cut.set("k", "v", null)).doesNotThrowAnyException();
  }

  @Test
  void delete_swallowsException() {
    Cache broken = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(broken).evict(any());
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(broken);
    assertThatCode(() -> cut.delete("k")).doesNotThrowAnyException();
  }

  @Test
  void clear_swallowsException() {
    Cache broken = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(broken).clear();
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(broken);
    assertThatCode(cut::clear).doesNotThrowAnyException();
  }

  @Test
  void get_nullValueWrapper_returnsEmpty() {
    Cache emptyCache = mock(Cache.class);
    when(emptyCache.get("k")).thenReturn(null);
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(emptyCache);
    assertThat(cut.get("k")).isEmpty();
  }

  @Test
  void get_wrapperReturnsNullValue_returnsEmpty() {
    Cache cacheWithNullValue = mock(Cache.class);
    Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
    when(wrapper.get()).thenReturn(null);
    when(cacheWithNullValue.get("k")).thenReturn(wrapper);
    SpringCacheSecurityCache cut = new SpringCacheSecurityCache(cacheWithNullValue);
    assertThat(cut.get("k")).isEmpty();
  }
}
