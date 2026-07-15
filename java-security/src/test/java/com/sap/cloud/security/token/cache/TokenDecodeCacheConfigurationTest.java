/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.cache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class TokenDecodeCacheConfigurationTest {

  @Test
  void disabled_hasZeroDurationAndSize() {
    TokenDecodeCacheConfiguration cfg = TokenDecodeCacheConfiguration.disabled();
    assertThat(cfg.isCacheDisabled()).isTrue();
    assertThat(cfg.getCacheDuration()).isEqualTo(Duration.ZERO);
    assertThat(cfg.getCacheSize()).isZero();
    assertThat(cfg.isCacheStatisticsEnabled()).isFalse();
  }

  @Test
  void enabledDefaultSize_returnsExpectedValues() {
    TokenDecodeCacheConfiguration cfg =
        TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(1));
    assertThat(cfg.isCacheDisabled()).isFalse();
    assertThat(cfg.getCacheDuration()).isEqualTo(Duration.ofMinutes(1));
    assertThat(cfg.getCacheSize()).isEqualTo(10_000);
  }

  @Test
  void enabledExplicitSize_returnsExpectedValues() {
    TokenDecodeCacheConfiguration cfg =
        TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(1), 200);
    assertThat(cfg.getCacheSize()).isEqualTo(200);
  }

  @Test
  void enabled_rejectsInvalidInputs() {
    assertThatThrownBy(() -> TokenDecodeCacheConfiguration.enabled(null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> TokenDecodeCacheConfiguration.enabled(Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> TokenDecodeCacheConfiguration.enabled(Duration.ofSeconds(-1)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(1), 0))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(1), -1))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
