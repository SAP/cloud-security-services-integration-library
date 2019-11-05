package com.sap.cloud.security.xsuaa.jwk;

import static com.sap.cloud.security.xsuaa.jwk.JSONWebKeyConstants.*;

import javax.annotation.Nullable;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.sap.cloud.security.xsuaa.Assertions;

public class JsonWebKeyImpl implements JsonWebKey {
	private Type type;
	private String keyId;
	private String algorithm;
	private String pemEncodedPublicKey;
	private String modulus;
	private String publicExponent;

	public JsonWebKeyImpl(Type type, @Nullable String keyId, @Nullable String algorithm, String modulus, String publicExponent, @Nullable String pemEncodedPublicKey) {
		Assertions.assertNotNull(type, "type must be not null");
		this.type = type;
		this.keyId = keyId != null ? keyId : DEFAULT_KEY_ID;
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
		if(pemEncodedPublicKey != null) {
			return createPublicKeyFromPemEncodedPubliKey(type, pemEncodedPublicKey);
		} else if (type == Type.RSA) {
			return createRSAPublicKey(publicExponent, modulus);
		}
		throw new IllegalStateException("JWT token with web key type " + type + " can not be verified.");
	}

	static PublicKey createRSAPublicKey(String publicExponent, String modulus)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		BigInteger n = new BigInteger(1, Base64.getUrlDecoder().decode(modulus));
		BigInteger e = new BigInteger(1, Base64.getUrlDecoder().decode(publicExponent));
		KeySpec keySpec = new RSAPublicKeySpec(n, e);

		KeyFactory keyFactory = KeyFactory.getInstance(Type.RSA.value());
		return keyFactory.generatePublic(keySpec);
	}

	static PublicKey createPublicKeyFromPemEncodedPubliKey(JsonWebKeyImpl.Type type, String pemEncodedKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decodedBytes = Base64.getMimeDecoder().decode(convertPEMKey(pemEncodedKey));

		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(decodedBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(type.value());
		return keyFactory.generatePublic(keySpecX509);
	}

	public static String convertPEMKey(String pemEncodedKey) {
		String key = pemEncodedKey;
		key = key.replace(BEGIN_PUBLIC_KEY, "");
		key = key.replace(END_PUBLIC_KEY, "");
		return key;
	}

}

