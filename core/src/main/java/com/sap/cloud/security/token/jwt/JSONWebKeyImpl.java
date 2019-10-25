package com.sap.cloud.security.token.jwt;

import javax.annotation.Nullable;

import java.security.PublicKey;

public class JSONWebKeyImpl implements JSONWebKey {
	JSONWebKey.Type type;
	String keyId;
	String algorithm;
	String pemEncodedPublicKey;
	PublicKey publicKey;

	public JSONWebKeyImpl(JSONWebKey.Type type, String keyId, String algorithm, String pemEncodedPublicKey, PublicKey publicKey) {
		// TODO check required fields
		this.type = type;
		this.keyId = keyId;
		this.algorithm = algorithm;
		this.pemEncodedPublicKey = pemEncodedPublicKey;
		this.publicKey = publicKey;
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

	@Override public PublicKey getPublicKey() {
		return publicKey;
	}
}

