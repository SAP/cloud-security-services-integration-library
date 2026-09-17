/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.BEGIN_PUBLIC_KEY;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.END_PUBLIC_KEY;

/**
 * Algorithm-typed carrier for the raw parameters a JWK contributes to key construction.
 * Splitting these fields out of {@link JsonWebKeyImpl} keeps each key type's parameter set
 * self-contained: an {@link Rsa} record cannot accidentally reach EC-specific code and vice
 * versa, which the previous "flat bag of nullable strings" constructor made too easy.
 * <p>
 * Sealed to a closed set of implementations — adding a new JWK key type (e.g. OKP for EdDSA)
 * means adding one more record and one more case, not another optional constructor parameter.
 */
sealed interface KeyMaterial permits KeyMaterial.Rsa, KeyMaterial.Ec, KeyMaterial.Pem {

	PublicKey toPublicKey(JwtSignatureAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException;

	/** RSA JWK: {@code n} (modulus) and {@code e} (public exponent), both base64url-encoded. */
	record Rsa(String modulus, String publicExponent) implements KeyMaterial {
		@Override
		public PublicKey toPublicKey(JwtSignatureAlgorithm algorithm)
				throws NoSuchAlgorithmException, InvalidKeySpecException {
			BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(modulus));
			BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(publicExponent));
			return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
		}
	}

	/**
	 * EC JWK: {@code crv} + affine coordinates {@code x}/{@code y} per RFC 7518 §6.2.1.
	 * The strict validation done here (curve/algorithm match, exact coordinate length) exists
	 * because a short or truncated coordinate would otherwise produce a key on the wrong
	 * subgroup and silently succeed.
	 */
	record Ec(String curve, String xCoordinate, String yCoordinate) implements KeyMaterial {
		@Override
		public PublicKey toPublicKey(JwtSignatureAlgorithm algorithm)
				throws NoSuchAlgorithmException, InvalidKeySpecException {
			if (curve == null || xCoordinate == null || yCoordinate == null) {
				throw new InvalidKeySpecException(
						"EC JWK is missing required parameters 'crv', 'x' or 'y' for algorithm " + algorithm.value());
			}
			if (!curve.equals(algorithm.curveName())) {
				throw new InvalidKeySpecException("EC JWK curve '" + curve + "' does not match algorithm "
						+ algorithm.value() + " which requires '" + algorithm.curveName() + "'.");
			}
			byte[] xBytes = Base64.getUrlDecoder().decode(xCoordinate);
			byte[] yBytes = Base64.getUrlDecoder().decode(yCoordinate);
			int expectedLength = algorithm.coordinateLength();
			if (xBytes.length != expectedLength || yBytes.length != expectedLength) {
				throw new InvalidKeySpecException("EC JWK coordinates for " + algorithm.value()
						+ " must be " + expectedLength + " octets each (got x=" + xBytes.length + ", y="
						+ yBytes.length + ").");
			}

			ECPoint point = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
			ECParameterSpec ecParameterSpec;
			try {
				AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
				// SunEC's AlgorithmParameters accepts "P-256" but not "P-384"/"P-521" as a curve
				// name; the standard NIST names work for all three. Map JWK → NIST to stay portable.
				parameters.init(new ECGenParameterSpec(toJcaCurveName(curve)));
				ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
			} catch (InvalidParameterSpecException e) {
				throw new InvalidKeySpecException("EC curve " + curve + " is not supported by the JCA provider.", e);
			}
			return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, ecParameterSpec));
		}

		private static String toJcaCurveName(String jwkCurveName) throws InvalidKeySpecException {
			return switch (jwkCurveName) {
				case "P-256" -> "secp256r1";
				case "P-384" -> "secp384r1";
				case "P-521" -> "secp521r1";
				default -> throw new InvalidKeySpecException("Unsupported EC curve: " + jwkCurveName);
			};
		}
	}

	/**
	 * PEM-encoded {@code SubjectPublicKeyInfo} (used by the XSUAA JKU response format). The
	 * enclosing algorithm's {@code kty} tells JCA which {@link KeyFactory} to load.
	 */
	record Pem(String pemEncodedKey) implements KeyMaterial {
		@Override
		public PublicKey toPublicKey(JwtSignatureAlgorithm algorithm)
				throws NoSuchAlgorithmException, InvalidKeySpecException {
			byte[] decodedBytes = Base64.getMimeDecoder().decode(stripDelimiters(pemEncodedKey));
			return KeyFactory.getInstance(algorithm.type())
					.generatePublic(new X509EncodedKeySpec(decodedBytes));
		}

		static String stripDelimiters(String pem) {
			return pem.replace(BEGIN_PUBLIC_KEY, "").replace(END_PUBLIC_KEY, "");
		}
	}
}