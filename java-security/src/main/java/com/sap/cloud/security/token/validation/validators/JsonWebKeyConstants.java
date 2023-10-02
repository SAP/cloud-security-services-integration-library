/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

class JsonWebKeyConstants {

	private JsonWebKeyConstants() {
	}

	static final String RSA_KEY_MODULUS_PARAMETER_NAME = "n";
	static final String RSA_KEY_PUBLIC_EXPONENT_PARAMETER_NAME = "e";

	// Parameter names as defined in https://tools.ietf.org/html/rfc7517
	static final String KEYS_PARAMETER_NAME = "keys";
	static final String KEY_TYPE_PARAMETER_NAME = "kty";
	static final String ALG_HEADER = "alg";
	static final String VALUE_PARAMETER_NAME = "value";
	static final String JKU_HEADER = "jku";
	static final String KID_HEADER = "kid";

	// Legacy Token Key ID
	static final String KEY_ID_VALUE_LEGACY = "legacy-token-key";

	static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
}
