package com.sap.cloud.security.xsuaa.jwt;

import javax.annotation.Nullable;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.sap.cloud.security.xsuaa.Assertions;

public class JSONWebKeyImpl implements JSONWebKey {
	JSONWebKey.Type type;
	String keyId;
	String algorithm;
	String pemEncodedPublicKey;
	String modulus;
	String publicExponent;

	public JSONWebKeyImpl(JSONWebKey.Type type, @Nullable String keyId, @Nullable String algorithm, String modulus, String publicExponent, @Nullable String pemEncodedPublicKey) {
		Assertions.assertNotNull(type, "type must be not null");
		this.type = type;
		this.keyId = keyId != null ? keyId : JSONWebKey.DEFAULT_KEY_ID;
		this.algorithm = algorithm;
		this.pemEncodedPublicKey = pemEncodedPublicKey;
		this.publicExponent = publicExponent;
		this.modulus = modulus;
	}

	@Nullable @Override public String getAlgorithm() {
		return algorithm;
	}

	@Nullable @Override public Type getType() {
		return type;
	}

	@Nullable @Override public String getId() {
		return keyId;
	}

	@Override public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		if(type == JSONWebKey.Type.RSA) {
			if(pemEncodedPublicKey != null) {
				return createPublicKeyFromPemEncodedPubliKey(type, pemEncodedPublicKey);
			}
			return createRSAPublicKey(publicExponent, modulus);
		}
		throw new IllegalStateException("JWT token with web key type " + type + " can not be verified.");
	}

	static PublicKey createRSAPublicKey(String publicExponent, String modulus)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory keyFactory = KeyFactory.getInstance(JSONWebKey.Type.RSA.value());
		BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(modulus));
		BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(publicExponent));
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(n, e);
		return keyFactory.generatePublic(keySpec);
	}

	static PublicKey createPublicKeyFromPemEncodedPubliKey(JSONWebKeyImpl.Type type, String pemEncodedKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decodedBytes = Base64.getDecoder().decode(convertPEMKey(pemEncodedKey));

		KeyFactory keyFactory = KeyFactory.getInstance(type.value());
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(decodedBytes);
		return keyFactory.generatePublic(keySpecX509);
	}

	public static String convertPEMKey(String pemEncodedKey) {
		String key = pemEncodedKey;
		key = key.replace(JSONWebKeyConstants.BEGIN_PUBLIC_KEY, "");
		key = key.replace(JSONWebKeyConstants.END_PUBLIC_KEY, "");
		key = key.replace("\n", "");
		key = key.replace("\\n", "");
		return key;
	}

}

