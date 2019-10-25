package com.sap.cloud.security.token.jwt;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JSONWebKeyFactory {

	private JSONWebKeyFactory() {
	}

	public static JSONWebKeySet createFromJSON(String json) throws InvalidKeySpecException, NoSuchAlgorithmException {
		String kid = "key-id-1"; //TODO parse from JSON
		String kty = "RSA"; //TODO parse from JSON
		String alg = "RS256"; //TODO parse from JSON
		String value = "----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmNM3OXfZS0Uu8eYZXCgG\\nWFgVWQX6MHnadYk3zHZ5PIPeDY3ApaSGpMEiVwn1cT6KUVHMLHcmz1gsNy74pCnm\\nCa22W7J3BoZulzR0A37ayMVrRHh3nffgySk8u581l02bvbcpab3e3EotSN5LixGT\\n1VWZvDbalXf6n5kq459NWL6ZzkEs20MrOEk5cLdnsigTQUHSKIQ5TpldyDkJMm2z\\nwOlrB2R984+QdlDFmoVH7Yaujxr2g0Z96u7W9Imik6wTiFc8W7eUXfhPGn7reVLq\\n1/5o2Nz0Jx0ejFHDwTGncs+k1RBS6DbpTOMr9tkJEc3ZsX3Ft4OtqCkRXI5hUma+\\nHwIDAQAB\\n-----END PUBLIC KEY-----"; //TODO parse from JSON

		PublicKey publicKey = createPublicKey(kty, value);
		JSONWebKeySet jwks = new JSONWebKeySet();
		JSONWebKey jwk = new JSONWebKeyImpl(JSONWebKey.Type.valueOf(kty), kid, alg, value, publicKey);
		jwks.put(jwk);
		return jwks;
	}

	static PublicKey createPublicKey(String keyType, String pemEncodedPublicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance(keyType); // "RSA"

		String publicKey = pemEncodedPublicKey.replaceAll("\\n", "").replaceAll("\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");


		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
		return keyFactory.generatePublic(keySpecX509);
	}

}
