package com.sap.cloud.security.xsuaa.jwk;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JsonWebKeySet {

	private Set<JsonWebKey> jsonWebKeys;

	public JsonWebKeySet() {
		jsonWebKeys = new HashSet<>();
	}

	@Nullable
	public JsonWebKey getKeyByTypeAndId(JsonWebKey.Type keyType, String keyId) {
		return getTokenStreamWithTypeAndKeyId(keyType, keyId)
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

	private Stream<JsonWebKey> getTokenStreamWithTypeAndKeyId(JsonWebKey.Type keyType, String keyId) {
		String kid = keyId != null ? keyId : JsonWebKey.DEFAULT_KEY_ID;
		return jsonWebKeys.stream()
				.filter(jwk -> keyType.equals(jwk.getType()))
				.filter(jwk -> kid.equals(jwk.getId()));
	}
}
