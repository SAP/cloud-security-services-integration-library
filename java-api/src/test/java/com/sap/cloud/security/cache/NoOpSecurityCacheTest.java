/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class NoOpSecurityCacheTest {

  private final SecurityCache<String, String> cache = new NoOpSecurityCache<>();

  @Test
  void getReturnsEmpty() {
    assertThat(cache.get("any-key")).isEmpty();
  }

  @Test
  void setDoesNotStoreAndDoesNotThrow() {
    assertThatCode(() -> cache.set("k", "v", Duration.ofSeconds(30))).doesNotThrowAnyException();
    assertThat(cache.get("k")).isEmpty();
  }

  @Test
  void setWithNullTtlDoesNotThrow() {
    assertThatCode(() -> cache.set("k", "v", null)).doesNotThrowAnyException();
  }

  @Test
  void deleteDoesNotThrow() {
    assertThatCode(() -> cache.delete("k")).doesNotThrowAnyException();
  }

  @Test
  void clearDoesNotThrow() {
    assertThatCode(cache::clear).doesNotThrowAnyException();
  }
}
