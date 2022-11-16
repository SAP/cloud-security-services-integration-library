/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import org.json.JSONArray;
import org.json.JSONObject;

class JsonWebKeySetFactory {

	private JsonWebKeySetFactory() {
	}

	static JsonWebKeySet createFromJson(String json) {
		JsonWebKeySet keySet = new JsonWebKeySet();
		if (json != null) {
			JSONArray keys = new JSONObject(json).getJSONArray(JsonWebKeyConstants.KEYS_PARAMETER_NAME);

			for (Object key : keys) {
				if (key instanceof JSONObject) {
					keySet.put(createJsonWebKey((JSONObject) key));
				}
			}
		}
		return keySet;
	}

	private static JsonWebKey createJsonWebKey(JSONObject key) {
		String keyAlgorithm = null;
		String pemEncodedPublicKey = null;
		String keyId = null;
		String modulus = null;
		String publicExponent = null;

		String keyType = key.getString(JsonWebKeyConstants.KEY_TYPE_PARAMETER_NAME);
		if (key.has(JsonWebKeyConstants.ALGORITHM_PARAMETER_NAME)) {
			keyAlgorithm = key.getString(JsonWebKeyConstants.ALGORITHM_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.VALUE_PARAMETER_NAME)) {
			pemEncodedPublicKey = key.getString(JsonWebKeyConstants.VALUE_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.KEY_ID_PARAMETER_NAME)) {
			keyId = key.getString(JsonWebKeyConstants.KEY_ID_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME)) {
			modulus = key.getString(JsonWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME)) {
			publicExponent = key.getString(JsonWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME);
		}
		JwtSignatureAlgorithm algorithm = keyAlgorithm != null ? JwtSignatureAlgorithm.fromValue(keyAlgorithm)
				: JwtSignatureAlgorithm.fromType(keyType);

		return new JsonWebKeyImpl(algorithm, keyId, modulus, publicExponent,
				pemEncodedPublicKey);
	}

}
