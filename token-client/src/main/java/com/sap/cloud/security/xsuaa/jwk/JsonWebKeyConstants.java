package com.sap.cloud.security.xsuaa.jwk;

public class JsonWebKeyConstants {

	private JsonWebKeyConstants() {
	}

	public static final String RSA_KEY_MODULUS_PARAMETER_NAME = "n";
	public static final String RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME = "e";

	// Parameter names as defined in https://tools.ietf.org/html/rfc7517
	public static final String KEYS_PARAMETER_NAME = "keys";
	public static final String KEY_TYPE_PARAMETER_NAME = "kty";
	public static final String ALGORITHM_PARAMETER_NAME = "alg";
	public static final String VALUE_PARAMETER_NAME = "value";
	public static final String KEYS_URL_PARAMETER_NAME = "jku";
	public static final String KEY_ID_PARAMETER_NAME = "kid";

	// Legacy Token Key ID
	public static final String KEY_ID_VALUE_LEGACY = "legacy-token-key";

	static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
}
