/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache.jcache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import javax.cache.Cache;
import javax.cache.CacheManager;
import javax.cache.Caching;
import javax.cache.configuration.MutableConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JCacheSecurityCacheTest {

  private CacheManager mgr;
  private Cache<String, String> jcache;
  private JCacheSecurityCache cut;

  @BeforeEach
  void setup() {
    mgr = Caching.getCachingProvider().getCacheManager();
    MutableConfiguration<String, String> cfg =
        new MutableConfiguration<String, String>()
            .setTypes(String.class, String.class)
            .setStoreByValue(false);
    jcache = mgr.createCache("test-cache", cfg);
    cut = new JCacheSecurityCache(jcache);
  }

  @AfterEach
  void tearDown() {
    mgr.destroyCache("test-cache");
    mgr.close();
  }

  @Test
  void getMissReturnsEmpty() {
    assertThat(cut.get("missing")).isEmpty();
  }

  @Test
  void setThenGetHits() {
    cut.set("k", "v", Duration.ofMinutes(1));
    assertThat(cut.get("k")).contains("v");
  }

  @Test
  void deleteRemovesEntry() {
    cut.set("k", "v", null);
    cut.delete("k");
    assertThat(cut.get("k")).isEmpty();
  }

  @Test
  void clearRemovesAll() {
    cut.set("k1", "v1", null);
    cut.set("k2", "v2", null);
    cut.clear();
    assertThat(cut.get("k1")).isEmpty();
    assertThat(cut.get("k2")).isEmpty();
  }

  @Test
  void get_swallowsRuntimeExceptionAndReturnsEmpty() {
    @SuppressWarnings("unchecked")
    Cache<String, String> broken = mock(Cache.class);
    when(broken.get(any())).thenThrow(new RuntimeException("boom"));
    JCacheSecurityCache adapter = new JCacheSecurityCache(broken);
    assertThat(adapter.get("k")).isEmpty();
  }

  @Test
  void set_swallowsRuntimeException() {
    @SuppressWarnings("unchecked")
    Cache<String, String> broken = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(broken).put(any(), any());
    JCacheSecurityCache adapter = new JCacheSecurityCache(broken);
    assertThatCode(() -> adapter.set("k", "v", null)).doesNotThrowAnyException();
  }

  @Test
  void delete_swallowsRuntimeException() {
    @SuppressWarnings("unchecked")
    Cache<String, String> broken = mock(Cache.class);
    when(broken.remove(any())).thenThrow(new RuntimeException("boom"));
    JCacheSecurityCache adapter = new JCacheSecurityCache(broken);
    assertThatCode(() -> adapter.delete("k")).doesNotThrowAnyException();
  }

  @Test
  void clear_swallowsRuntimeException() {
    @SuppressWarnings("unchecked")
    Cache<String, String> broken = mock(Cache.class);
    doThrow(new RuntimeException("boom")).when(broken).clear();
    JCacheSecurityCache adapter = new JCacheSecurityCache(broken);
    assertThatCode(adapter::clear).doesNotThrowAnyException();
  }
}
