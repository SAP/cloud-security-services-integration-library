package com.sap.cloud.security.xsuaa.jwt;


import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class JsonWebKeySetFactoryTest {

	private String jsonWebKeySet;

	@Before
	public void setup() throws IOException {
		jsonWebKeySet = IOUtils.resourceToString("/JSONWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Test
	public void containsKey() {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJSON(jsonWebKeySet);
		assertThat(jwks.isEmpty(), equalTo(false));
		assertThat(jwks.containsKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-0"), equalTo(true));
		assertThat(jwks.containsKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-1"), equalTo(true));
	}

	@Test
	public void getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJSON(jsonWebKeySet);
		JsonWebKey jwk = jwks.getKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-1");
		assertThat(jwk.getAlgorithm(), equalTo("RS256"));
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getKeys() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJSON(jsonWebKeySet);
		JsonWebKey jwk = jwks.getKeyByTypeAndId(JsonWebKey.Type.RSA, "key-id-1");
		assertThat(jwk.getAlgorithm(), equalTo("RS256"));
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getIasKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		jsonWebKeySet = IOUtils.resourceToString("/iasJSONWebTokenKeys.json", StandardCharsets.UTF_8);
		JsonWebKeySet jwks = JsonWebKeySetFactory.createFromJSON(jsonWebKeySet);
		JsonWebKey jwk = jwks.getKeyByTypeAndId(JsonWebKey.Type.RSA, null);
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo(JsonWebKey.DEFAULT_KEY_ID));
	}
}
