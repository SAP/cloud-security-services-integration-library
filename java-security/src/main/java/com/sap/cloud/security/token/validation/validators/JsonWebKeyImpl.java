/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.xsuaa.Assertions;

import jakarta.annotation.Nullable;
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
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.BEGIN_PUBLIC_KEY;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.END_PUBLIC_KEY;

class JsonWebKeyImpl implements JsonWebKey {
	private final JwtSignatureAlgorithm keyAlgorithm;
	private final String keyId;
	private final String pemEncodedPublicKey;
	private final String modulus;
	private final String publicExponent;
	private final String curve;
	private final String xCoordinate;
	private final String yCoordinate;
	private PublicKey publicKey;

	JsonWebKeyImpl(JwtSignatureAlgorithm keyAlgorithm, @Nullable String keyId, String modulus,
			String publicExponent, @Nullable String pemEncodedPublicKey) {
		this(keyAlgorithm, keyId, modulus, publicExponent, null, null, null, pemEncodedPublicKey);
	}

	JsonWebKeyImpl(JwtSignatureAlgorithm keyAlgorithm, @Nullable String keyId, @Nullable String modulus,
			@Nullable String publicExponent, @Nullable String curve, @Nullable String xCoordinate,
			@Nullable String yCoordinate, @Nullable String pemEncodedPublicKey) {
		Assertions.assertNotNull(keyAlgorithm, "keyAlgorithm must be not null");
		this.keyId = keyId != null ? keyId : DEFAULT_KEY_ID;

		this.pemEncodedPublicKey = pemEncodedPublicKey;
		this.publicExponent = publicExponent;
		this.modulus = modulus;
		this.curve = curve;
		this.xCoordinate = xCoordinate;
		this.yCoordinate = yCoordinate;
		this.keyAlgorithm = keyAlgorithm;
	}

	@Override
	public JwtSignatureAlgorithm getKeyAlgorithm() {
		return keyAlgorithm;
	}

	@Nullable
	@Override
	public String getId() {
		return keyId;
	}

	@Override
	public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (publicKey != null) {
			return publicKey;
		}
		if (pemEncodedPublicKey != null) {
			publicKey = createPublicKeyFromPemEncodedPublicKey(keyAlgorithm, pemEncodedPublicKey);
		} else if (keyAlgorithm.type().equalsIgnoreCase("RSA")) {
			publicKey = createRSAPublicKey(publicExponent, modulus);
		} else if (keyAlgorithm.type().equalsIgnoreCase("EC")) {
			publicKey = createECPublicKey(keyAlgorithm, curve, xCoordinate, yCoordinate);
		} else {
			throw new IllegalStateException("JWT token with web key type " + keyAlgorithm + " can not be verified.");
		}
		return publicKey;
	}

	static PublicKey createRSAPublicKey(String publicExponent, String modulus)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(modulus));
		BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(publicExponent));
		KeySpec keySpec = new RSAPublicKeySpec(n, e);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}

	/**
	 * Builds an EC {@link PublicKey} from JWK {@code crv}/{@code x}/{@code y} parameters per
	 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1">RFC 7518 §6.2.1</a>.
	 * <p>
	 * Validates that {@code crv} matches the curve expected by {@code algorithm} and that both
	 * coordinates have the exact octet length mandated for that curve — a missing or short
	 * coordinate would otherwise produce a key on the wrong subgroup and silently succeed.
	 */
	static PublicKey createECPublicKey(JwtSignatureAlgorithm algorithm, String curve, String xCoordinate,
			String yCoordinate) throws NoSuchAlgorithmException, InvalidKeySpecException {
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
					+ " must be " + expectedLength + " octets each (got x=" + xBytes.length + ", y=" + yBytes.length + ").");
		}

		ECPoint point = new ECPoint(new BigInteger(1, xBytes), new BigInteger(1, yBytes));
		ECParameterSpec ecParameterSpec;
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			// SunEC's AlgorithmParameters accepts "P-256" but not "P-384"/"P-521" as a curve name;
			// the standard NIST names work for all three. Map JWK → NIST to stay portable.
			parameters.init(new ECGenParameterSpec(toJcaCurveName(curve)));
			ecParameterSpec = parameters.getParameterSpec(ECParameterSpec.class);
		} catch (InvalidParameterSpecException e) {
			throw new InvalidKeySpecException("EC curve " + curve + " is not supported by the JCA provider.", e);
		}
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		return keyFactory.generatePublic(new ECPublicKeySpec(point, ecParameterSpec));
	}

	private static String toJcaCurveName(String jwkCurveName) throws InvalidKeySpecException {
		switch (jwkCurveName) {
			case "P-256": return "secp256r1";
			case "P-384": return "secp384r1";
			case "P-521": return "secp521r1";
			default: throw new InvalidKeySpecException("Unsupported EC curve: " + jwkCurveName);
		}
	}

	public static PublicKey createPublicKeyFromPemEncodedPublicKey(JwtSignatureAlgorithm algorithm,
			String pemEncodedKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decodedBytes = Base64.getMimeDecoder().decode(convertPEMKey(pemEncodedKey));

		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(decodedBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm.type());
		return keyFactory.generatePublic(keySpecX509);
	}

	public static String convertPEMKey(String pemEncodedKey) {
		String key = pemEncodedKey;
		key = key.replace(BEGIN_PUBLIC_KEY, "");
		key = key.replace(END_PUBLIC_KEY, "");
		return key;
	}

	@Override
	public int hashCode() {
		return Objects.hash(keyAlgorithm, keyId != null ? keyId : DEFAULT_KEY_ID);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		JsonWebKeyImpl that = (JsonWebKeyImpl) o;

		if (getKeyAlgorithm() != that.getKeyAlgorithm())
			return false;
		return keyId.equals(that.keyId);
	}

	@Override
	public String toString() {
		return getId() + "(" + getKeyAlgorithm() + ")";
	}

}
