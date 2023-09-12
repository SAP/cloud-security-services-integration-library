/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

class JsonWebKeySet {

	private final Set<JsonWebKey> jsonWebKeys = new HashSet<>();
	@Deprecated
	private final Set<String> appTidAccepted = new HashSet<>();

	@Nullable
	public JsonWebKey getKeyByAlgorithmAndId(JwtSignatureAlgorithm keyAlgorithm, String keyId) {
		return getTokenStreamWithTypeAndKeyId(keyAlgorithm, keyId)
				.findFirst()
				.orElse(null);
	}

	public Set<JsonWebKey> getAll() {
		return jsonWebKeys;
	}

	public boolean put(@Nonnull JsonWebKey jsonWebKey) {
		return jsonWebKeys.add(jsonWebKey);
	}

	public void putAll(JsonWebKeySet jsonWebKeySet) {
		jsonWebKeys.addAll(jsonWebKeySet.getAll());
	}

	private Stream<JsonWebKey> getTokenStreamWithTypeAndKeyId(JwtSignatureAlgorithm algorithm, String keyId) {
		String kid = keyId != null ? keyId : JsonWebKey.DEFAULT_KEY_ID;
		return jsonWebKeys.stream()
				.filter(jwk -> algorithm.equals(jwk.getKeyAlgorithm()))
				.filter(jwk -> kid.equals(jwk.getId()));
	}

	@Deprecated
	public boolean containsAppTid(String appTid) {
		return appTidAccepted.contains(appTid);
	}

	@Deprecated
	public boolean isAppTidAccepted(String appTid) {
		return appTidAccepted.contains(appTid);
	}

	@Deprecated
	public JsonWebKeySet withAppTid(String appTid, boolean isAccepted) {
		if(isAccepted) {
			appTidAccepted.add(appTid);
		} else {
			appTidAccepted.remove(appTid);
		}

		return this;
	}

	public String toString() {
		return jsonWebKeys.stream().map(String::valueOf).collect(Collectors.joining("|"));
	}
}
