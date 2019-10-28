package com.sap.cloud.security.xsuaa.jwt;


import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

public class JSONWebKeyFactoryTest {

	private String jsonWebKeySet;

	@Before
	public void setup() throws IOException {
		jsonWebKeySet = IOUtils.resourceToString("/JSONWebTokenKeys.json", StandardCharsets.UTF_8);
	}

	@Test
	public void containsKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JSONWebKeySet jwks = JSONWebKeyFactory.createFromJSON(jsonWebKeySet);
		assertThat(jwks.isEmpty(), equalTo(false));
		assertThat(jwks.containsKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-0"), equalTo(true));
		assertThat(jwks.containsKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-1"), equalTo(true));
	}

	@Test
	public void getKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JSONWebKeySet jwks = JSONWebKeyFactory.createFromJSON(jsonWebKeySet);
		JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-1");
		assertThat(jwk.getAlgorithm(), equalTo("RS256"));
		assertThat(jwk.getType().value, equalTo("RSA"));
		assertThat(jwk.getPublicKeyPemEncoded(), startsWith(JSONWebKeyConstants.BEGIN_PUBLIC_KEY));
		assertThat(jwk.getId(), equalTo("key-id-1"));
		assertThat(jwk.getPublicKey(), startsWith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmNM3OXfZS0Uu8eYZXCgGW"));
		assertThat(jwk.getPublicKey(), endsWith("kJEc3ZsX3Ft4OtqCkRXI5hUma+HwIDAQAB"));
	}

	@Test
	public void getOtherKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		JSONWebKeySet jwks = JSONWebKeyFactory.createFromJSON(jsonWebKeySet);
		JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, "key-id-0");
		assertThat(jwk.getId(), equalTo("key-id-0"));

	}
}
