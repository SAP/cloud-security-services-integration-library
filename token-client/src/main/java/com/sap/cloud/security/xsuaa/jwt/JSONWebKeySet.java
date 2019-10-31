package com.sap.cloud.security.xsuaa.jwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class JSONWebKeySet {

	private Set<JSONWebKey> jsonWebKeys;

	public JSONWebKeySet(Collection<JSONWebKey> jsonWebKeys) {
		this.jsonWebKeys = jsonWebKeys.stream().collect(Collectors.toSet());
	}

	public JSONWebKeySet() {
		jsonWebKeys = new HashSet<>();
	}

	public boolean isEmpty() {
		return jsonWebKeys.isEmpty();
	}

	public boolean containsKeyByTypeAndId(JSONWebKey.Type keyType, String keyId) {
		return getTokenStreamWithTypeAndKeyId(keyType, keyId)
				.findAny()
				.isPresent();
	}

	@Nullable
	public JSONWebKey getKeyByTypeAndId(JSONWebKey.Type keyType, String keyId) {
		return getTokenStreamWithTypeAndKeyId(keyType, keyId)
				.findFirst()
				.orElse(null);
	}

	public boolean put(@Nonnull JSONWebKey jsonWebKey) {
		if (containsKeyByTypeAndId(jsonWebKey.getType(), jsonWebKey.getId())) {
			return false;
		} else {
			jsonWebKeys.add(jsonWebKey);
			return true;
		}
	}

	private Stream<JSONWebKey> getTokenStreamWithTypeAndKeyId(JSONWebKey.Type keyType, String keyId) {
		String kid = keyId != null ? keyId : JSONWebKey.DEFAULT_KEY_ID;
		return jsonWebKeys.stream()
				.filter(jwk -> keyType.equals(jwk.getType()))
				.filter(jwk -> kid.equals(jwk.getId()));
	}
}
