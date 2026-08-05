/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

class JsonWebKeySetFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(JsonWebKeySetFactory.class);

	private JsonWebKeySetFactory() {
	}

	static JsonWebKeySet createFromJson(String json) {
		JsonWebKeySet keySet = new JsonWebKeySet();
		if (json != null) {
			JSONArray keys = new JSONObject(json).getJSONArray(JsonWebKeyConstants.KEYS_PARAMETER_NAME);

			for (Object key : keys) {
				if (key instanceof JSONObject) {
					JsonWebKey jwk = tryCreateJsonWebKey((JSONObject) key);
					if (jwk != null) {
						keySet.put(jwk);
					}
				}
			}
		}
		return keySet;
	}

	/**
	 * Wraps {@link #createJsonWebKey(JSONObject)} so that a single malformed or unsupported entry does not tear down
	 * the whole JWKS. This is important because identity providers may add keys for algorithms we do not (yet)
	 * support (e.g. new EC curves, EdDSA, ...); dropping the full key set would break token validation for all
	 * tenants that share this JWKS endpoint, including tokens signed with algorithms we DO support.
	 */
	@Nullable
	private static JsonWebKey tryCreateJsonWebKey(JSONObject key) {
		try {
			return createJsonWebKey(key);
		} catch (RuntimeException e) {
			LOGGER.warn("Skipping JWK entry that could not be parsed (kid={}, kty={}, alg={}) in JWKS: {}",
					key.optString(JsonWebKeyConstants.KID_PARAMETER_NAME, "<none>"),
					key.optString(JsonWebKeyConstants.KEY_TYPE_PARAMETER_NAME, "<none>"),
					key.optString(JsonWebKeyConstants.ALG_PARAMETER_NAME, "<none>"),
					e.getMessage());
			return null;
		}
	}

	@Nullable
	private static JsonWebKey createJsonWebKey(JSONObject key) {
		String keyAlgorithm = null;
		String pemEncodedPublicKey = null;
		String keyId = null;
		String modulus = null;
		String publicExponent = null;

		String keyType = key.getString(JsonWebKeyConstants.KEY_TYPE_PARAMETER_NAME);
		if (key.has(JsonWebKeyConstants.ALG_PARAMETER_NAME)) {
			keyAlgorithm = key.getString(JsonWebKeyConstants.ALG_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.VALUE_PARAMETER_NAME)) {
			pemEncodedPublicKey = key.getString(JsonWebKeyConstants.VALUE_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.KID_PARAMETER_NAME)) {
			keyId = key.getString(JsonWebKeyConstants.KID_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME)) {
			modulus = key.getString(JsonWebKeyConstants.RSA_KEY_MODULUS_PARAMETER_NAME);
		}
		if (key.has(JsonWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME)) {
			publicExponent = key.getString(JsonWebKeyConstants.RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME);
		}
		JwtSignatureAlgorithm algorithm = keyAlgorithm != null ? JwtSignatureAlgorithm.fromValue(keyAlgorithm)
				: JwtSignatureAlgorithm.fromType(keyType);

		if (algorithm == null) {
			// Neither the JWA "alg" value (e.g. "ES256") nor the JWK "kty" (e.g. "EC") mapped to a signature algorithm
			// we support. Skip this JWK instead of failing the whole set — the JWKS may still contain other keys we
			// can validate with.
			LOGGER.info("Skipping JWK entry with unsupported algorithm (kid={}, kty={}, alg={}) in JWKS.",
					keyId != null ? keyId : "<none>",
					keyType,
					keyAlgorithm != null ? keyAlgorithm : "<none>");
			return null;
		}

		return new JsonWebKeyImpl(algorithm, keyId, modulus, publicExponent,
				pemEncodedPublicKey);
	}

}
