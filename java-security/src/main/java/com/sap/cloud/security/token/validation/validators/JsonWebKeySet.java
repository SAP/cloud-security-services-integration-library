package com.sap.cloud.security.token.validation.validators;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

class JsonWebKeySet {

	private Set<JsonWebKey> jsonWebKeys;

	JsonWebKeySet() {
		jsonWebKeys = new HashSet<>();
	}

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
}
