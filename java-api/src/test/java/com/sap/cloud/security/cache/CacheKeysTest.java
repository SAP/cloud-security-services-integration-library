/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CacheKeysTest {

  @Test
  void buildIsStableForSameFingerprint() {
    String a = CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, "fingerprint-1");
    String b = CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, "fingerprint-1");
    assertThat(a).isEqualTo(b);
  }

  @Test
  void buildProducesDifferentKeyForDifferentFingerprint() {
    String a = CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, "fingerprint-1");
    String b = CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, "fingerprint-2");
    assertThat(a).isNotEqualTo(b);
  }

  @Test
  void buildProducesDifferentKeyForDifferentNamespace() {
    String tokensKey = CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, "same-fp");
    String jwksKey = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, "same-fp");
    assertThat(tokensKey).isNotEqualTo(jwksKey);
  }

  @Test
  void buildHasExpectedFormat() {
    String key = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, "abc");
    // sap-security:<namespace>:<64 hex chars>
    assertThat(key).matches("^sap-security:jwks:[0-9a-f]{64}$");
  }

  @Test
  void buildProducesExpectedSha256() {
    // SHA-256("abc") =
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    String key = CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, "abc");
    assertThat(key)
        .isEqualTo(
            "sap-security:tokens:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  }

  @Test
  void allNamespacesAreDistinct() {
    assertThat(CacheKeys.NAMESPACE_TOKENS).isNotEqualTo(CacheKeys.NAMESPACE_JWKS);
    assertThat(CacheKeys.NAMESPACE_TOKENS).isNotEqualTo(CacheKeys.NAMESPACE_OIDC);
    assertThat(CacheKeys.NAMESPACE_TOKENS).isNotEqualTo(CacheKeys.NAMESPACE_DECODE);
    assertThat(CacheKeys.NAMESPACE_TOKENS).isNotEqualTo(CacheKeys.NAMESPACE_SIG);
    assertThat(CacheKeys.NAMESPACE_JWKS).isNotEqualTo(CacheKeys.NAMESPACE_OIDC);
    assertThat(CacheKeys.NAMESPACE_OIDC).isNotEqualTo(CacheKeys.NAMESPACE_DECODE);
    assertThat(CacheKeys.NAMESPACE_DECODE).isNotEqualTo(CacheKeys.NAMESPACE_SIG);
  }

  @Test
  void prefixReturnsExpectedValue() {
    assertThat(CacheKeys.prefix()).isEqualTo("sap-security:");
  }

  @Test
  void allBuiltKeysStartWithPrefix() {
    assertThat(CacheKeys.build(CacheKeys.NAMESPACE_TOKENS, "x")).startsWith(CacheKeys.prefix());
    assertThat(CacheKeys.build(CacheKeys.NAMESPACE_SIG, "x")).startsWith(CacheKeys.prefix());
  }
}
