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

class SignatureValidationCacheConfigurationTest {

  private static final byte[] IKM = "some-app-ikm".getBytes();

  @Test
  void disabled_hasZeroDurationAndSize() {
    SignatureValidationCacheConfiguration cfg = SignatureValidationCacheConfiguration.disabled();
    assertThat(cfg.isCacheDisabled()).isTrue();
    assertThat(cfg.getCacheDuration()).isEqualTo(Duration.ZERO);
    assertThat(cfg.getCacheSize()).isZero();
    assertThat(cfg.isCacheStatisticsEnabled()).isFalse();
    assertThat(cfg.getIkm()).isEmpty();
  }

  @Test
  void enabledDefaultSize_returnsExpectedValues() {
    SignatureValidationCacheConfiguration cfg =
        SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(1), IKM);
    assertThat(cfg.isCacheDisabled()).isFalse();
    assertThat(cfg.getCacheDuration()).isEqualTo(Duration.ofMinutes(1));
    assertThat(cfg.getCacheSize()).isEqualTo(10_000);
    assertThat(cfg.getIkm()).isEqualTo(IKM);
  }

  @Test
  void enabledExplicitSize_returnsExpectedValues() {
    SignatureValidationCacheConfiguration cfg =
        SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(1), 500, IKM);
    assertThat(cfg.getCacheSize()).isEqualTo(500);
  }

  @Test
  void getIkm_returnsDefensiveCopy() {
    SignatureValidationCacheConfiguration cfg =
        SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(1), IKM);
    byte[] first = cfg.getIkm();
    first[0] = (byte) 0xFF;
    byte[] second = cfg.getIkm();
    assertThat(second).isEqualTo(IKM); // internal state unchanged
    assertThat(second).isNotSameAs(first);
  }

  @Test
  void enabled_rejectsInvalidInputs() {
    assertThatThrownBy(() -> SignatureValidationCacheConfiguration.enabled(null, IKM))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> SignatureValidationCacheConfiguration.enabled(Duration.ZERO, IKM))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> SignatureValidationCacheConfiguration.enabled(Duration.ofSeconds(-1), IKM))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(1), 0, IKM))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(1), null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> SignatureValidationCacheConfiguration.enabled(Duration.ofMinutes(1), new byte[0]))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
