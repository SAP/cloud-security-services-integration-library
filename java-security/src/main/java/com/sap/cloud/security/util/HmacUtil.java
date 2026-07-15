/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA256 (RFC 5869) and HMAC-SHA256 helpers used by the opt-in signature validation cache.
 *
 * <p>The helpers here are intentionally minimal — just what {@link
 * com.sap.cloud.security.token.cache.SignatureValidationCache} needs to derive a per-application
 * HMAC key from client credentials and to sign / verify cached signature-validation results.
 */
public final class HmacUtil {

  private static final String HMAC_SHA256 = "HmacSHA256";
  private static final int SHA256_LEN = 32;

  private HmacUtil() {}

  /**
   * HKDF-SHA256, RFC 5869, salt-less (all-zeros salt). Combines {@code extract} and {@code expand}
   * into a single call because the cache only ever needs one 32-byte output block.
   *
   * @param ikm the input keying material
   * @param info the context / application-specific info string
   * @param length the desired number of output bytes; must be less than or equal to 32 (one SHA-256
   *     block) for this simplified implementation. That's enough for a 256-bit HMAC key.
   * @return the derived key material of {@code length} bytes
   */
  public static byte[] hkdfSha256(final byte[] ikm, final byte[] info, final int length) {
    if (length <= 0 || length > SHA256_LEN) {
      throw new IllegalArgumentException("length must be in 1..32 for this HKDF impl");
    }
    // Extract: PRK = HMAC-SHA256(salt=0-block, IKM)
    byte[] salt = new byte[SHA256_LEN];
    byte[] prk = hmacSha256(salt, ikm);
    // Expand N=1: T1 = HMAC(PRK, info || 0x01)
    byte[] data = new byte[info.length + 1];
    System.arraycopy(info, 0, data, 0, info.length);
    data[info.length] = 0x01;
    byte[] t1 = hmacSha256(prk, data);
    byte[] out = new byte[length];
    System.arraycopy(t1, 0, out, 0, length);
    return out;
  }

  /** HMAC-SHA256(key, data). */
  public static byte[] hmacSha256(final byte[] key, final byte[] data) {
    try {
      Mac mac = Mac.getInstance(HMAC_SHA256);
      mac.init(new SecretKeySpec(key, HMAC_SHA256));
      return mac.doFinal(data);
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("HmacSHA256 must be available on every JVM", e);
    } catch (final InvalidKeyException e) {
      throw new IllegalStateException("HMAC key rejected: " + e.getMessage(), e);
    }
  }

  /**
   * Constant-time equals for two byte arrays. Delegates to
   * {@link MessageDigest#isEqual(byte[], byte[])} which is documented to be constant-time on
   * modern JDKs.
   */
  public static boolean verify(final byte[] a, final byte[] b) {
    if (a == null || b == null) {
      return false;
    }
    return MessageDigest.isEqual(a, b);
  }

  /** UTF-8 encode; small helper to keep call-sites tidy. */
  public static byte[] utf8(final String s) {
    return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
  }
}
