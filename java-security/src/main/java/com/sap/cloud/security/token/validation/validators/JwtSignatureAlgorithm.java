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
 *   <li>the {@code kty} JWK key type ({@code RSA} for RS* and PS* families),
 *   <li>the {@code alg} value as it appears in JWK and JWT headers,
 *   <li>the corresponding standard JCA signature algorithm name passed to
 *       {@link java.security.Signature#getInstance(String)},
 *   <li>an optional {@link AlgorithmParameterSpec} for algorithms that require explicit
 *       parameters (RSASSA-PSS).
 * </ul>
 */
public enum JwtSignatureAlgorithm {

	RS256("RSA", "RS256", "SHA256withRSA", null, 0),
	RS384("RSA", "RS384", "SHA384withRSA", null, 0),
	RS512("RSA", "RS512", "SHA512withRSA", null, 0),

	PS256("RSA", "PS256", "RSASSA-PSS", "SHA-256", 32),
	PS384("RSA", "PS384", "RSASSA-PSS", "SHA-384", 48),
	PS512("RSA", "PS512", "RSASSA-PSS", "SHA-512", 64);

	private final String type;
	private final String value;
	private final String javaSignatureAlgorithm;
	@Nullable
	private final AlgorithmParameterSpec parameterSpec;

	JwtSignatureAlgorithm(String type, String algorithm, String javaSignatureAlgorithm,
			@Nullable String pssHashAlgorithm, int pssSaltLength) {
		this.type = type;
		this.value = algorithm; // jwks, jwt header
		this.javaSignatureAlgorithm = javaSignatureAlgorithm;
		this.parameterSpec = pssHashAlgorithm == null
				? null
				: new PSSParameterSpec(pssHashAlgorithm, "MGF1",
						new MGF1ParameterSpec(pssHashAlgorithm), pssSaltLength, 1);
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