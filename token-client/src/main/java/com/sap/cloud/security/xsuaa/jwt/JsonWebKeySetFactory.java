package com.sap.cloud.security.xsuaa.jwt;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashSet;
import java.util.Set;

public class JsonWebKeySetFactory {

	private JsonWebKeySetFactory() {
	}

	public static JsonWebKeySet createFromJSON(String json) {
		JSONArray keys = new JSONObject(json).getJSONArray(JSONWebKeyConstants.KEYS_PARAMETER_NAME);
		Set<JsonWebKey> jsonWebKeys = extractJsonWebKeys(keys);
		return new JsonWebKeySet(jsonWebKeys);
	}

	private static Set<JsonWebKey> extractJsonWebKeys(JSONArray keys) {
		Set<JsonWebKey> jsonWebKeys = new HashSet<>();
		for (Object key : keys) {
			if (key instanceof JSONObject) {
				jsonWebKeys.add(createJSONWebKey((JSONObject) key));
			}
		}
		return jsonWebKeys;
	}

	private static JsonWebKey createJSONWebKey(JSONObject key) {
		String algorithm = null;
		String pemEncodedPublicKey = null;
		String keyId = null;
		String modulus = null;
		String publicExponent = null;

		String keyType = key.getString(JSONWebKeyConstants.KEY_TYPE_PARAMETER_NAME);
		if(key.has(JSONWebKeyConstants.ALGORITHM_PARAMETER_NAME)) {
			algorithm = key.getString(JSONWebKeyConstants.ALGORITHM_PARAMETER_NAME);
		}
		if(key.has(JSONWebKeyConstants.VALUE_PARAMETER_NAME)) {
			pemEncodedPublicKey = key.getString(JSONWebKeyConstants.VALUE_PARAMETER_NAME);
		}
		if(key.has(JSONWebKeyConstants.KEY_ID_PARAMETER_NAME)) {
			keyId = key.getString(JSONWebKeyConstants.KEY_ID_PARAMETER_NAME);
		}
		if(key.has(JSONWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME)) {
			modulus = key.getString(JSONWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME);
		}
		if(key.has(JSONWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME)) {
			publicExponent = key.getString(JSONWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME);
		}
		return new JsonWebKeyImpl(JsonWebKey.Type.valueOf(keyType), keyId, algorithm, modulus, publicExponent, pemEncodedPublicKey);
	}

}
