package com.sap.cloud.security.token;

/**
 * Class with constants denoting Jwt header parameters.
 * https://tools.ietf.org/html/rfc7515#section-4
 */
public final class TokenHeader {
	private TokenHeader() {
		throw new IllegalStateException("Utility class");
	}

	public static final String ALGORITHM = "alg";
	public static final String JWKS_URL = "jku";
	public static final String KEY_ID = "kid";
	public static final String TYPE = "typ";
}