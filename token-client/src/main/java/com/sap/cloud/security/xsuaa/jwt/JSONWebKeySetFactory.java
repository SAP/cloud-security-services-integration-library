package com.sap.cloud.security.xsuaa.jwt;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashSet;
import java.util.Set;

public class JSONWebKeySetFactory {

	private JSONWebKeySetFactory() {
	}

	public static JSONWebKeySet createFromJSON(String json) {
		JSONArray keys = new JSONObject(json).getJSONArray(JSONWebKeyConstants.KEYS_PARAMETER_NAME);
		Set<JSONWebKey> jsonWebKeys = extractJsonWebKeys(keys);
		return new JSONWebKeySet(jsonWebKeys);
	}

	private static Set<JSONWebKey> extractJsonWebKeys(JSONArray keys) {
		Set<JSONWebKey> jsonWebKeys = new HashSet<>();
		for (Object key : keys) {
			if (key instanceof JSONObject) {
				jsonWebKeys.add(createJSONWebKey((JSONObject) key));
			}
		}
		return jsonWebKeys;
	}

	private static JSONWebKey createJSONWebKey(JSONObject key) {
		String keyType = key.getString(JSONWebKeyConstants.KEY_TYPE_PARAMETER_NAME);
		String algorithm = key.getString(JSONWebKeyConstants.ALGORITHM_PARAMETER_NAME);
		String pemEncodedPublicKey = key.getString(JSONWebKeyConstants.VALUE_PARAMETER_NAME);
		String keyId = key.getString(JSONWebKeyConstants.KEY_ID_PARAMETER_NAME);
		return new JSONWebKeyImpl(JSONWebKey.Type.valueOf(keyType), keyId, algorithm, pemEncodedPublicKey);
	}

}
