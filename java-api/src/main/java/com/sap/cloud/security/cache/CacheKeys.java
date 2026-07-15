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
 * Utilities for building stable, opaque cache keys.
 *
 * <p>All cache keys produced by the SAP Cloud Security libraries follow the pattern
 * <pre>{@code sap-security:<namespace>:<sha256-hex>}</pre>
 * where the namespace identifies the cache (e.g. {@code tokens}, {@code jwks}, {@code oidc},
 * {@code decode}, {@code sig}) and the hex string is the SHA-256 digest of the full request
 * fingerprint.
 *
 * <p>Hashing is performed for two reasons:
 * <ol>
 *   <li>Request fingerprints for the token cache contain credentials
 *       ({@code client_secret}, {@code password}, {@code assertion}). Hashing keeps them out of
 *       the key material stored in a distributed cache.
 *   <li>Uniform key length regardless of input size — friendlier for shared cache stores.
 * </ol>
 *
 * <p>The prefix {@code sap-security:} allows implementations backed by a shared store to scope
 * {@link SecurityCache#clear()} to library-owned entries and to identify entries at a glance in
 * cache-management UIs.
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

  /** Namespace for parsed-token (decode) cache entries. */
  public static final String NAMESPACE_DECODE = "decode";

  /** Namespace for signature-validation-result cache entries. */
  public static final String NAMESPACE_SIG = "sig";

  private static final String PREFIX = "sap-security:";

  private CacheKeys() {
    // utility class
  }

  /**
   * Builds an opaque cache key of the form {@code sap-security:<namespace>:<sha256-hex>}.
   *
   * @param namespace the cache namespace, e.g. {@link #NAMESPACE_TOKENS}
   * @param fingerprint the fingerprint of the request — any string that uniquely identifies the
   *     entry, including all parameters that affect the response
   * @return the opaque cache key
   */
  public static String build(final String namespace, final String fingerprint) {
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
