package com.sap.cloud.security.token;

/**
 * Class with constants denoting Jwt header parameters.
 * https://tools.ietf.org/html/rfc7515#section-4
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