package com.sap.cloud.security.xsuaa.jwt;

import javax.annotation.Nullable;

public class JSONWebKeyImpl implements JSONWebKey {
	JSONWebKey.Type type;
	String keyId;
	String algorithm;
	String pemEncodedPublicKey;

	public JSONWebKeyImpl(JSONWebKey.Type type, String keyId, String algorithm, String pemEncodedPublicKey) {
		// TODO check required fields
		this.type = type;
		this.keyId = keyId;
		this.algorithm = algorithm;
		this.pemEncodedPublicKey = pemEncodedPublicKey;
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

	@Override public String getPublicKeyPemEncoded() {
		return pemEncodedPublicKey;
	}

	@Override public String getPublicKey() {
		return convertPEMKey(pemEncodedPublicKey);
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

