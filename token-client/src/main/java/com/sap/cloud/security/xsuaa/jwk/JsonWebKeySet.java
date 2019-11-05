package com.sap.cloud.security.xsuaa.jwk;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.util.HashMap;

import com.sap.cloud.security.xsuaa.Assertions;

public class JsonWebKeySet {

	private HashMap<String, JsonWebKey> jsonWebKeys;

	public JsonWebKeySet() {
		jsonWebKeys = new HashMap<>();
	}

	public boolean isEmpty() {
		return jsonWebKeys.isEmpty();
	}

	public boolean containsKeyByTypeAndId(JsonWebKey.Type keyType, String keyId) {
		return jsonWebKeys.containsKey(String.valueOf(JsonWebKeyImpl.calculateUniqueId(keyType, keyId)));
	}

	@Nullable
	public JsonWebKey getKeyByTypeAndId(@Nonnull JsonWebKey.Type keyType, @Nonnull String keyId) {
		return jsonWebKeys.get(String.valueOf(JsonWebKeyImpl.calculateUniqueId(keyType, keyId)));
	}

	public boolean put(@Nonnull JsonWebKey jsonWebKey) {
		Assertions.assertNotNull(jsonWebKey, "jsonWebKey must not be null");

		if (containsKeyByTypeAndId(jsonWebKey.getType(), jsonWebKey.getId())) {
			return false;
		} else {
			jsonWebKeys.put(String.valueOf(jsonWebKey.hashCode()), jsonWebKey);
			return true;
		}
	}

	public void putAll(JsonWebKeySet jsonWebKeySet) {
		jsonWebKeys.putAll(jsonWebKeySet.jsonWebKeys);
	}

	public void clear() {
		jsonWebKeys.clear();
	}
}
