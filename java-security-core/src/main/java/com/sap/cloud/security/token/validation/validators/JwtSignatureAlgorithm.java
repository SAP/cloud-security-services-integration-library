/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import jakarta.annotation.Nullable;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * JWT signature algorithms supported during token validation, as specified in
 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.1">RFC 7518 §3.1</a>.
 * <p>
 * Each entry carries:
 * <ul>
 *   <li>the {@code kty} JWK key type ({@code RSA} for RS* and PS* families, {@code EC} for ES*),
 *   <li>the {@code alg} value as it appears in JWK and JWT headers,
 *   <li>the corresponding standard JCA signature algorithm name passed to
 *       {@link java.security.Signature#getInstance(String)},
 *   <li>an optional {@link AlgorithmParameterSpec} for algorithms that require explicit
 *       parameters (RSASSA-PSS),
 *   <li>for EC algorithms: the curve name ({@code P-256}/{@code P-384}/{@code P-521}) and the
 *       fixed coordinate length in octets per RFC 7518 §6.2.1.
 * </ul>
 * <p>
 * For ECDSA the JCA name {@code SHA*withECDSAinP1363Format} is used so that
 * {@link java.security.Signature#verify(byte[])} accepts the raw {@code R||S} concatenation
 * mandated by RFC 7518 §3.4 directly, without DER transcoding.
 */
public enum JwtSignatureAlgorithm {

	RS256("RSA", "RS256", "SHA256withRSA", null, 0),
	RS384("RSA", "RS384", "SHA384withRSA", null, 0),
	RS512("RSA", "RS512", "SHA512withRSA", null, 0),

	PS256("RSA", "PS256", "RSASSA-PSS", "SHA-256", 32),
	PS384("RSA", "PS384", "RSASSA-PSS", "SHA-384", 48),
	PS512("RSA", "PS512", "RSASSA-PSS", "SHA-512", 64),

	ES256("EC", "ES256", "SHA256withECDSAinP1363Format", "P-256", 32),
	ES384("EC", "ES384", "SHA384withECDSAinP1363Format", "P-384", 48),
	ES512("EC", "ES512", "SHA512withECDSAinP1363Format", "P-521", 66);

	private final String type;
	private final String value;
	private final String javaSignatureAlgorithm;
	@Nullable
	private final AlgorithmParameterSpec parameterSpec;
	@Nullable
	private final String curveName;
	private final int coordinateLength;

	JwtSignatureAlgorithm(String type, String algorithm, String javaSignatureAlgorithm,
			@Nullable String extraParam, int saltOrCoordinateLength) {
		this.type = type;
		this.value = algorithm; // jwks, jwt header
		this.javaSignatureAlgorithm = javaSignatureAlgorithm;
		if ("EC".equals(type)) {
			this.parameterSpec = null;
			this.curveName = extraParam;
			this.coordinateLength = saltOrCoordinateLength;
		} else {
			this.parameterSpec = extraParam == null
					? null
					: new PSSParameterSpec(extraParam, "MGF1",
							new MGF1ParameterSpec(extraParam), saltOrCoordinateLength, 1);
			this.curveName = null;
			this.coordinateLength = 0;
		}
	}

	public String value() {
		return value;
	}

	public String javaSignature() {
		return javaSignatureAlgorithm;
	}

	public String type() {
		return type;
	}

	/**
	 * @return additional JCA parameters required to verify a signature with this algorithm, or
	 * 		{@code null} if no parameters are needed (the default for everything except RSASSA-PSS).
	 */
	@Nullable
	public AlgorithmParameterSpec parameterSpec() {
		return parameterSpec;
	}

	/**
	 * For EC algorithms: the JWK curve name as defined in
	 * <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.1">RFC 7518 §6.2.1.1</a>
	 * ({@code P-256}, {@code P-384}, or {@code P-521}). Returns {@code null} for RSA-based algorithms.
	 */
	@Nullable
	public String curveName() {
		return curveName;
	}

	/**
	 * For EC algorithms: the required octet length of each of the {@code x} and {@code y} coordinates
	 * of the public key per RFC 7518 §6.2.1.2/§6.2.1.3 (32/48/66 for P-256/P-384/P-521). Returns
	 * {@code 0} for RSA-based algorithms.
	 */
	public int coordinateLength() {
		return coordinateLength;
	}

	public static JwtSignatureAlgorithm fromValue(String value) {
		for (JwtSignatureAlgorithm algorithm : values()) {
			if (algorithm.value.equals(value)) {
				return algorithm;
			}
		}
		return null;
	}

	/**
	 * Returns the default algorithm for the given JWK key type. Used as a fallback when a JWK
	 * entry omits its {@code alg}.
	 * <p>
	 * When multiple algorithms share a {@code kty}, the first match in enum declaration order
	 * wins — currently {@link #RS256} for {@code RSA}. Preserve that order when adding new
	 * algorithms (e.g. EC): put the canonical RFC 7518 default at the top of its {@code kty}
	 * group. The choice is only advisory; downstream key construction still cross-checks the
	 * concrete JWK parameters (curve, coordinate length, …) against the returned algorithm,
	 * so a mismatched default produces a clear error rather than a silently wrong key.
	 */
	public static JwtSignatureAlgorithm fromType(String type) {
		for (JwtSignatureAlgorithm algorithm : values()) {
			if (algorithm.type.equals(type)) {
				return algorithm;
			}
		}
		return null;
	}
}