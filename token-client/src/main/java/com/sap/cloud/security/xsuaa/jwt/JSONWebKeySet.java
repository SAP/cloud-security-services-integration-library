package com.sap.cloud.security.xsuaa.jwt;

public class JSONWebKeySet {
	//TODO List of <JSONWebKey>
	JSONWebKey jsonWebKey;
	public boolean isEmpty() {
		throw new RuntimeException("JSONWebKeySet.isEmpty not yet implemented"); // TODO
	}

	public boolean containsKeyByTypeAndId(JSONWebKey.Type keyType, String keyId) {
		throw new RuntimeException("JSONWebKeySet.containsKeyByTypeAndId not yet implemented"); // TODO
	}

	public JSONWebKey getKeyByTypeAndId(JSONWebKey.Type keyType, String keyId) {
		return jsonWebKey; // TODO
	}


	public boolean put(JSONWebKey jsonWebKey) {
		this.jsonWebKey = jsonWebKey;
		return true; // TODO
	}
}
