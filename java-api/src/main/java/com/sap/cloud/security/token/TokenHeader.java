/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

/**
 * Constants denoting Jwt header parameters.
 * <a href="https://tools.ietf.org/html/rfc7515#section-4">https://tools.ietf.org/html/rfc7515#section-4</a>
 */
public final class TokenHeader {
	private TokenHeader() {
		throw new IllegalStateException("Utility class");
	}

	public static final String ALGORITHM = "alg"; // Algorithm Header Parameter
	public static final String JWKS_URL = "jku"; // JWK Set URL Header Parameter
	public static final String KEY_ID = "kid"; // Key ID Header Parameter
	public static final String TYPE = "typ"; // Type Header Parameter
}