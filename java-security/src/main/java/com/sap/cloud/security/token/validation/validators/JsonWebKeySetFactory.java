/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
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
		String keyType = key.getString(JsonWebKeyConstants.KEY_TYPE_PARAMETER_NAME);
		String keyAlgorithmName = optionalString(key, JsonWebKeyConstants.ALG_PARAMETER_NAME);
		String keyId = optionalString(key, JsonWebKeyConstants.KID_PARAMETER_NAME);

		JwtSignatureAlgorithm algorithm = keyAlgorithmName != null
				? JwtSignatureAlgorithm.fromValue(keyAlgorithmName)
				: JwtSignatureAlgorithm.fromType(keyType);

		return new JsonWebKeyImpl(algorithm, keyId, extractKeyMaterial(key));
	}

	/**
	 * Chooses the appropriate {@link KeyMaterial} carrier for a JWK entry. PEM ({@code value})
	 * takes precedence — that's the XSUAA JKU response format, which supplies the key as a
	 * pre-encoded {@code SubjectPublicKeyInfo} regardless of {@code kty}. Otherwise a JWK with a
	 * {@code crv} field is EC; anything else is treated as RSA (the historical default).
	 */
	private static KeyMaterial extractKeyMaterial(JSONObject key) {
		String pem = optionalString(key, JsonWebKeyConstants.VALUE_PARAMETER_NAME);
		if (pem != null) {
			return new KeyMaterial.Pem(pem);
		}
		if (key.has(JsonWebKeyConstants.EC_CURVE_PARAMETER_NAME)) {
			return new KeyMaterial.Ec(
					key.getString(JsonWebKeyConstants.EC_CURVE_PARAMETER_NAME),
					optionalString(key, JsonWebKeyConstants.EC_X_COORDINATE_PARAMETER_NAME),
					optionalString(key, JsonWebKeyConstants.EC_Y_COORDINATE_PARAMETER_NAME));
		}
		return new KeyMaterial.Rsa(
				optionalString(key, JsonWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME),
				optionalString(key, JsonWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME));
	}

	private static String optionalString(JSONObject key, String field) {
		return key.has(field) ? key.getString(field) : null;
	}

}