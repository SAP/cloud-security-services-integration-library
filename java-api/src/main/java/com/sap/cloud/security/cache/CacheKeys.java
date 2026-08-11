/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Utilities for building stable cache keys for the SAP Cloud Security libraries.
 *
 * <p>All keys follow the pattern {@code sap-security:<namespace>:<fingerprint>} where the
 * namespace identifies the cache (e.g. {@code tokens}, {@code jwks}, {@code oidc}).
 *
 * <p>The prefix {@code sap-security:} allows implementations backed by a shared store to scope
 * {@link SecurityCache#clear()} to library-owned entries only.
 *
 * <p>Two key formats are provided:
 * <ul>
 *   <li>{@link #buildOpaque(String, String)} — SHA-256 hashes the fingerprint. Use for the
 *       <em>token cache</em>, where the fingerprint contains credentials
 *       ({@code client_secret}, {@code password}, {@code assertion}) that must not be stored in
 *       plain text in a distributed cache.
 *   <li>{@link #build(String, String)} — stores the fingerprint as-is. Use for JWKS and OIDC
 *       entries, which contain no credentials and benefit from human-readable keys for debugging.
 * </ul>
 *
 * @since 4.1.0
 */
public final class CacheKeys {

  /** Namespace for outbound token cache entries. */
  public static final String NAMESPACE_TOKENS = "tokens";

  /** Namespace for JWKS cache entries. */
  public static final String NAMESPACE_JWKS = "jwks";

  /** Namespace for OIDC discovery cache entries. */
  public static final String NAMESPACE_OIDC = "oidc";

  private static final String PREFIX = "sap-security:";

  private CacheKeys() {
    // utility class
  }

  /**
   * Builds a human-readable cache key of the form {@code sap-security:<namespace>:<fingerprint>}.
   *
   * <p>Use this for JWKS and OIDC entries where the fingerprint contains no credentials and
   * readability in a cache management UI is desirable.
   *
   * @param namespace the cache namespace, e.g. {@link #NAMESPACE_JWKS}
   * @param fingerprint the fingerprint of the request — any string that uniquely identifies the
   *     entry, including all parameters that affect the response
   * @return the cache key
   */
  public static String build(final String namespace, final String fingerprint) {
    return PREFIX + namespace + ":" + fingerprint;
  }

  /**
   * Builds an opaque cache key of the form {@code sap-security:<namespace>:<sha256-hex>}.
   *
   * <p>Use this for the token cache, where the fingerprint contains credentials
   * ({@code client_secret}, {@code password}, {@code assertion}) that must not be stored in plain
   * text in a distributed cache.
   *
   * @param namespace the cache namespace, e.g. {@link #NAMESPACE_TOKENS}
   * @param fingerprint the fingerprint of the request including all credential parameters
   * @return the opaque cache key
   */
  public static String buildOpaque(final String namespace, final String fingerprint) {
    return PREFIX + namespace + ":" + sha256Hex(fingerprint);
  }

  /**
   * @return the common key prefix used by the library — useful for adapters that want to scope
   *     {@link SecurityCache#clear()} to library entries only.
   */
  public static String prefix() {
    return PREFIX;
  }

  private static String sha256Hex(final String input) {
    try {
      final MessageDigest md = MessageDigest.getInstance("SHA-256");
      final byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    } catch (final NoSuchAlgorithmException e) {
      // SHA-256 is guaranteed to be available on every JVM implementing JCE.
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }
}