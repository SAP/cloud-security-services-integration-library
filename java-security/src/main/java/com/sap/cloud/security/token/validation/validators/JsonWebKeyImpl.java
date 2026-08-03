/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.xsuaa.Assertions;

import jakarta.annotation.Nullable;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

class JsonWebKeyImpl implements JsonWebKey {
	private final JwtSignatureAlgorithm keyAlgorithm;
	private final String keyId;
	private final KeyMaterial keyMaterial;
	private PublicKey publicKey;

	JsonWebKeyImpl(JwtSignatureAlgorithm keyAlgorithm, @Nullable String keyId, KeyMaterial keyMaterial) {
		Assertions.assertNotNull(keyAlgorithm, "keyAlgorithm must be not null");
		Assertions.assertNotNull(keyMaterial, "keyMaterial must be not null");
		this.keyAlgorithm = keyAlgorithm;
		this.keyId = keyId != null ? keyId : DEFAULT_KEY_ID;
		this.keyMaterial = keyMaterial;
	}

	@Override
	public JwtSignatureAlgorithm getKeyAlgorithm() {
		return keyAlgorithm;
	}

	@Nullable
	@Override
	public String getId() {
		return keyId;
	}

	@Override
	public PublicKey getPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (publicKey == null) {
			publicKey = keyMaterial.toPublicKey(keyAlgorithm);
		}
		return publicKey;
	}

	@Override
	public int hashCode() {
		return Objects.hash(keyAlgorithm, keyId);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;

		JsonWebKeyImpl that = (JsonWebKeyImpl) o;

		if (getKeyAlgorithm() != that.getKeyAlgorithm())
			return false;
		return keyId.equals(that.keyId);
	}

	@Override
	public String toString() {
		return getId() + "(" + getKeyAlgorithm() + ")";
	}

}