package com.sap.cloud.security.token;

import static com.sap.cloud.security.xsuaa.jwk.JsonWebKey.Type.*;

import com.sap.cloud.security.xsuaa.jwk.JsonWebKey;

public enum JwtSignatureAlgorithm {
	RS256(RSA, "RS256", "SHA256withRSA"),
	ES256(EC, "ES256", "SHA256withECDSA");

	private final String jwtAlgorithmHeaderValue;
	private final String javaSignatureAlgorithmName;
	private final JsonWebKey.Type keyType;

	JwtSignatureAlgorithm(JsonWebKey.Type keyType, String jwtAlgorithmHeaderValue, String javaSignatureAlgorithmName) {
		this.keyType = keyType;
		this.jwtAlgorithmHeaderValue = jwtAlgorithmHeaderValue;
		this.javaSignatureAlgorithmName = javaSignatureAlgorithmName;
	}

	public String asJwt() {
		return jwtAlgorithmHeaderValue;
	}

	public String asJava() {
		return javaSignatureAlgorithmName;
	}

	public JsonWebKey.Type getKeyType() {
		return keyType;
	}
}
