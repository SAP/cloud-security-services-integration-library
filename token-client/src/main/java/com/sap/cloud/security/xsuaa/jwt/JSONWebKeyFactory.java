package com.sap.cloud.security.xsuaa.jwt;

public class JSONWebKeyFactory {

	private JSONWebKeyFactory() {
	}

	public static JSONWebKeySet createFromJSON(String json) {
		String kid = "key-id-1"; //TODO parse from JSON
		String kty = "RSA"; //TODO parse from JSON
		String alg = "RS256"; //TODO parse from JSON
		String value = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmNM3OXfZS0Uu8eYZXCgG\\nWFgVWQX6MHnadYk3zHZ5PIPeDY3ApaSGpMEiVwn1cT6KUVHMLHcmz1gsNy74pCnm\\nCa22W7J3BoZulzR0A37ayMVrRHh3nffgySk8u581l02bvbcpab3e3EotSN5LixGT\\n1VWZvDbalXf6n5kq459NWL6ZzkEs20MrOEk5cLdnsigTQUHSKIQ5TpldyDkJMm2z\\nwOlrB2R984+QdlDFmoVH7Yaujxr2g0Z96u7W9Imik6wTiFc8W7eUXfhPGn7reVLq\\n1/5o2Nz0Jx0ejFHDwTGncs+k1RBS6DbpTOMr9tkJEc3ZsX3Ft4OtqCkRXI5hUma+\\nHwIDAQAB\\n-----END PUBLIC KEY-----"; //TODO parse from JSON

		JSONWebKeySet jwks = new JSONWebKeySet();
		JSONWebKey jwk = new JSONWebKeyImpl(JSONWebKey.Type.valueOf(kty), kid, alg, value);
		jwks.put(jwk);
		return jwks;
	}

}
