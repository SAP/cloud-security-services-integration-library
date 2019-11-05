package com.sap.cloud.security.xsuaa.jwk;

import org.json.JSONArray;
import org.json.JSONObject;

public class JsonWebKeySetFactory {

	private JsonWebKeySetFactory() {
	}

	public static JsonWebKeySet createFromJson(String json) {
		JSONArray keys = new JSONObject(json).getJSONArray(JsonWebKeyConstants.KEYS_PARAMETER_NAME);
		JsonWebKeySet keySet = new JsonWebKeySet();

		for (Object key : keys) {
			if (key instanceof JSONObject) {
				keySet.put(createJsonWebKey((JSONObject) key));
			}
		}
		return keySet;
	}

	private static JsonWebKey createJsonWebKey(JSONObject key) {
		String algorithm = null;
		String pemEncodedPublicKey = null;
		String keyId = null;
		String modulus = null;
		String publicExponent = null;

		String keyType = key.getString(JsonWebKeyConstants.KEY_TYPE_PARAMETER_NAME);
		if(key.has(JsonWebKeyConstants.ALGORITHM_PARAMETER_NAME)) {
			algorithm = key.getString(JsonWebKeyConstants.ALGORITHM_PARAMETER_NAME);
		}
		if(key.has(JsonWebKeyConstants.VALUE_PARAMETER_NAME)) {
			pemEncodedPublicKey = key.getString(JsonWebKeyConstants.VALUE_PARAMETER_NAME);
		}
		if(key.has(JsonWebKeyConstants.KEY_ID_PARAMETER_NAME)) {
			keyId = key.getString(JsonWebKeyConstants.KEY_ID_PARAMETER_NAME);
		}
		if(key.has(JsonWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME)) {
			modulus = key.getString(JsonWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME);
		}
		if(key.has(JsonWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME)) {
			publicExponent = key.getString(JsonWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME);
		}
		return new JsonWebKeyImpl(JsonWebKey.Type.valueOf(keyType), keyId, algorithm, modulus, publicExponent, pemEncodedPublicKey);
	}

}
