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
  void build_isStableForSameInput() {
    String a = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, "url:https://example.com|app_tid:t1");
    String b = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, "url:https://example.com|app_tid:t1");
    assertThat(a).isEqualTo(b);
  }

  @Test
  void build_hasExpectedPlaintextFormat() {
    String key = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, "url:https://example.com");
    assertThat(key).isEqualTo("jwks:url:https://example.com");
  }

  @Test
  void build_differentiatesByNamespace() {
    String jwks = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, "fp");
    String oidc = CacheKeys.build(CacheKeys.NAMESPACE_OIDC, "fp");
    assertThat(jwks).isNotEqualTo(oidc);
  }

  @Test
  void buildOpaque_isStableForSameInput() {
    String a = CacheKeys.buildOpaque(CacheKeys.NAMESPACE_TOKENS, "secret-fingerprint");
    String b = CacheKeys.buildOpaque(CacheKeys.NAMESPACE_TOKENS, "secret-fingerprint");
    assertThat(a).isEqualTo(b);
  }

  @Test
  void buildOpaque_hasExpectedSha256Format() {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    String key = CacheKeys.buildOpaque(CacheKeys.NAMESPACE_TOKENS, "abc");
    assertThat(key)
        .isEqualTo("tokens:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  }

  @Test
  void buildOpaque_doesNotExposeFingerprint() {
    String fingerprint = "client_secret=super-secret&grant_type=client_credentials";
    String key = CacheKeys.buildOpaque(CacheKeys.NAMESPACE_TOKENS, fingerprint);
    assertThat(key).doesNotContain("super-secret");
    assertThat(key).matches("^tokens:[0-9a-f]{64}$");
  }

  @Test
  void build_doesNotHash() {
    String fingerprint = "url:https://example.com";
    String key = CacheKeys.build(CacheKeys.NAMESPACE_JWKS, fingerprint);
    assertThat(key).contains(fingerprint);
  }

  @Test
  void namespacesAreDistinct() {
    assertThat(CacheKeys.NAMESPACE_TOKENS).isNotEqualTo(CacheKeys.NAMESPACE_JWKS);
    assertThat(CacheKeys.NAMESPACE_TOKENS).isNotEqualTo(CacheKeys.NAMESPACE_OIDC);
    assertThat(CacheKeys.NAMESPACE_JWKS).isNotEqualTo(CacheKeys.NAMESPACE_OIDC);
  }
}