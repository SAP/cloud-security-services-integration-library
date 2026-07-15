/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class HmacUtilTest {

  @Test
  void hkdfIsDeterministic() {
    byte[] a = HmacUtil.hkdfSha256("secret".getBytes(), "info".getBytes(), 32);
    byte[] b = HmacUtil.hkdfSha256("secret".getBytes(), "info".getBytes(), 32);
    assertThat(a).isEqualTo(b);
  }

  @Test
  void hkdfDiffersForDifferentIkm() {
    byte[] a = HmacUtil.hkdfSha256("secret1".getBytes(), "info".getBytes(), 32);
    byte[] b = HmacUtil.hkdfSha256("secret2".getBytes(), "info".getBytes(), 32);
    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void hkdfDiffersForDifferentInfo() {
    byte[] a = HmacUtil.hkdfSha256("secret".getBytes(), "info-a".getBytes(), 32);
    byte[] b = HmacUtil.hkdfSha256("secret".getBytes(), "info-b".getBytes(), 32);
    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void hkdfLengthIsHonored() {
    byte[] a = HmacUtil.hkdfSha256("secret".getBytes(), "info".getBytes(), 16);
    assertThat(a).hasSize(16);
  }

  @Test
  void hkdfRejectsInvalidLength() {
    assertThatThrownBy(() -> HmacUtil.hkdfSha256("s".getBytes(), "i".getBytes(), 0))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> HmacUtil.hkdfSha256("s".getBytes(), "i".getBytes(), 33))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void hmacRoundTrip() {
    byte[] key = "secret".getBytes();
    byte[] data = "hello world".getBytes();
    byte[] a = HmacUtil.hmacSha256(key, data);
    byte[] b = HmacUtil.hmacSha256(key, data);
    assertThat(a).isEqualTo(b);
    assertThat(a).hasSize(32);
  }

  @Test
  void hmacDiffersForBitFlippedData() {
    byte[] key = "secret".getBytes();
    byte[] a = HmacUtil.hmacSha256(key, "hello world".getBytes());
    byte[] b = HmacUtil.hmacSha256(key, "hello world!".getBytes());
    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void hmacDiffersForBitFlippedKey() {
    byte[] a = HmacUtil.hmacSha256("secret".getBytes(), "hello world".getBytes());
    byte[] b = HmacUtil.hmacSha256("SECRET".getBytes(), "hello world".getBytes());
    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void verifyIsConstantTimeEquals() {
    byte[] a = new byte[] {1, 2, 3, 4};
    byte[] b = new byte[] {1, 2, 3, 4};
    byte[] c = new byte[] {1, 2, 3, 5};
    assertThat(HmacUtil.verify(a, b)).isTrue();
    assertThat(HmacUtil.verify(a, c)).isFalse();
    assertThat(HmacUtil.verify(a, null)).isFalse();
    assertThat(HmacUtil.verify(null, b)).isFalse();
  }
}
