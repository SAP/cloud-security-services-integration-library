package com.sap.cloud.security.javasec.test;

public enum JwtSignatureAlgoritm {
	RS256("RS256", "SHA256withRSA");

	private final String jwtAlgorithmHeaderVale;
	private final String javaSignatureAlgorithmName;

	JwtSignatureAlgoritm(String jwtAlgorithmHeaderVale, String javaSignatureAlgorithmName) {
		this.jwtAlgorithmHeaderVale = jwtAlgorithmHeaderVale;
		this.javaSignatureAlgorithmName = javaSignatureAlgorithmName;
	}

	public String getJwtAlgorithmHeaderValue() {
		return jwtAlgorithmHeaderVale;
	}

	public String getJavaSignatureAlgorithmName() {
		return javaSignatureAlgorithmName;
	}
}
