package com.sap.cloud.security.token.validation;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.core.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.client.OAuth2TokenKeyService;
import com.sap.cloud.security.token.jwt.Base64JwtDecoder;
import com.sap.cloud.security.token.jwt.DecodedJwt;
import com.sap.cloud.security.token.jwt.JSONWebKey;
import com.sap.cloud.security.token.jwt.JSONWebKeyImpl;
import com.sap.cloud.security.token.jwt.JSONWebKeySet;


@Ignore
public class OAuth2TokenSignatureValidatorTest {
	private String pemEncodedPublicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmNM3OXfZS0Uu8eYZXCgG\nWFgVWQX6MHnadYk3zHZ5PIPeDY3ApaSGpMEiVwn1cT6KUVHMLHcmz1gsNy74pCnm\nCa22W7J3BoZulzR0A37ayMVrRHh3nffgySk8u581l02bvbcpab3e3EotSN5LixGT\n1VWZvDbalXf6n5kq459NWL6ZzkEs20MrOEk5cLdnsigTQUHSKIQ5TpldyDkJMm2z\nwOlrB2R984+QdlDFmoVH7Yaujxr2g0Z96u7W9Imik6wTiFc8W7eUXfhPGn7reVLq\n1/5o2Nz0Jx0ejFHDwTGncs+k1RBS6DbpTOMr9tkJEc3ZsX3Ft4OtqCkRXI5hUma+\nHwIDAQAB\n-----END PUBLIC KEY-----";
	private String accessToken;
	private OAuth2TokenSignatureValidator cut;
	private OAuth2TokenKeyService serviceMock;
	private OAuth2ServiceConfiguration serviceConfiguration;

	@Before
	public void setup() throws IOException {
		accessToken = IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8);

		serviceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(serviceConfiguration.getUaaUrl()).thenReturn(URI.create("https://subdomain.myauth.com"));

		serviceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(serviceMock.retrieveTokenKeys(any())).thenReturn(createJSONWebKeySet());

		cut = new OAuth2TokenSignatureValidator(serviceConfiguration, serviceMock);
	}

	private JSONWebKeySet createJSONWebKeySet() {
		//TODO PublicKey publicKey =
		JSONWebKey jsonWebKey = new JSONWebKeyImpl(
				JSONWebKey.Type.RSA, "key-id-1", "RS256", pemEncodedPublicKey, null);
		JSONWebKeySet keySet = new JSONWebKeySet();
		keySet.put(jsonWebKey);
		return keySet;
	}

	@Test
	public void checkAccessTokenIsCorrect() {
		DecodedJwt jwt = new Base64JwtDecoder().decode(accessToken);
		assertThat(cut.validate(jwt), is(true));
	}
}
