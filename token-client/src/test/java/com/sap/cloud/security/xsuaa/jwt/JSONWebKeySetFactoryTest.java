package com.sap.cloud.security.xsuaa.jwt;


import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class JSONWebKeySetFactoryTest {

	private String jsonWebKeySet;

	@Before
	public void setup() throws IOException {
		jsonWebKeySet = IOUtils.resourceToString("/JSONWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Test
	public void containsKey() {
		JSONWebKeySet jwks = JSONWebKeySetFactory.createFromJSON(jsonWebKeySet);
		assertThat(jwks.isEmpty(), equalTo(false));
		assertThat(jwks.containsKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-0"), equalTo(true));
		assertThat(jwks.containsKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-1"), equalTo(true));
	}

	@Test
	public void getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JSONWebKeySet jwks = JSONWebKeySetFactory.createFromJSON(jsonWebKeySet);
		JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-1");
		assertThat(jwk.getAlgorithm(), equalTo("RS256"));
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getKeys() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JSONWebKeySet jwks = JSONWebKeySetFactory.createFromJSON(jsonWebKeySet);
		JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-1");
		assertThat(jwk.getAlgorithm(), equalTo("RS256"));
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo("key-id-1"));
	}

	@Test
	public void getIasKeys() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		jsonWebKeySet = IOUtils.resourceToString("/iasJSONWebTokenKeys.json", StandardCharsets.UTF_8);
		JSONWebKeySet jwks = JSONWebKeySetFactory.createFromJSON(jsonWebKeySet);
		JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, null);
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKey().getAlgorithm(), equalTo(jwk.getType().value));
		assertThat(jwk.getId(), equalTo(JSONWebKey.DEFAULT_KEY_ID));
	}
}
