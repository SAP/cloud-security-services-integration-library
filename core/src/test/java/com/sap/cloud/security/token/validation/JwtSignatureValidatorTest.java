package com.sap.cloud.security.token.validation;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.core.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKey;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeyImpl;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;

public class JwtSignatureValidatorTest {
	private String pemEncodedPublicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmNM3OXfZS0Uu8eYZXCgG\nWFgVWQX6MHnadYk3zHZ5PIPeDY3ApaSGpMEiVwn1cT6KUVHMLHcmz1gsNy74pCnm\nCa22W7J3BoZulzR0A37ayMVrRHh3nffgySk8u581l02bvbcpab3e3EotSN5LixGT\n1VWZvDbalXf6n5kq459NWL6ZzkEs20MrOEk5cLdnsigTQUHSKIQ5TpldyDkJMm2z\nwOlrB2R984+QdlDFmoVH7Yaujxr2g0Z96u7W9Imik6wTiFc8W7eUXfhPGn7reVLq\n1/5o2Nz0Jx0ejFHDwTGncs+k1RBS6DbpTOMr9tkJEc3ZsX3Ft4OtqCkRXI5hUma+\nHwIDAQAB\n-----END PUBLIC KEY-----";
	private String accessToken;
	private String otherToken; // contains alg header only, signature that does not match jwks
	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService serviceMock;
	private OAuth2ServiceConfiguration serviceConfigurationMock;

	@Before
	public void setup() throws IOException {
		accessToken = IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		otherToken = IOUtils.resourceToString("/iasOIDCTokenAlgHeaderOnly.txt", StandardCharsets.UTF_8);

		serviceConfigurationMock = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(serviceConfigurationMock.getUaaUrl()).thenReturn(URI.create("https://subdomain.myauth.com"));

		serviceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(serviceMock.retrieveTokenKeys(any())).thenReturn(createJSONWebKeySet());

		cut = new JwtSignatureValidator(serviceConfigurationMock, serviceMock);
	}

	private JSONWebKeySet createJSONWebKeySet() {
		JSONWebKey jsonWebKey = new JSONWebKeyImpl(
				JSONWebKey.Type.RSA, "key-id-1", "RS256", pemEncodedPublicKey);
		JSONWebKeySet keySet = new JSONWebKeySet();
		keySet.put(jsonWebKey);
		return keySet;
	}

	@Test
	public void jsonWebSignatureMatchesJWKS() throws IOException {
		assertThat(cut.validate(decodedJwt(accessToken)).isValid(), is(true));
	}

	@Test
	public void jwtPayloadModifiedNotValid() {
		String[] tokenHeaderPayloadSignature = accessToken.split(Pattern.quote("."));
		String[] otherHeaderPayloadSignature = otherToken.split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(otherHeaderPayloadSignature[1])
				.append(".")
				.append(tokenHeaderPayloadSignature[2]).toString();
		assertThat(cut.validate(decodedJwt(tokenWithOthersSignature)).isValid(), is(false));
	}


	@Test
	public void validate_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.validate(null, "key-id-1", "RS256", "https://myauth.com/token_keys" );
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");

		assertThatThrownBy(() -> {
			cut.validate(accessToken, "", "RS256", "https://myauth.com/token_keys" );
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenKeyId");

		assertThatThrownBy(() -> {
			cut.validate(accessToken, "key-id-1", "", "https://myauth.com/token_keys" );
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenAlgorithm");

		assertThatThrownBy(() -> {
			cut.validate(accessToken, "key-id-1", "RS256", "" );
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenKeyUrl");
	}

	@Test
	public void jwtWithoutSignatureNotValid() {
		String[] tokenHeaderPayloadSignature = accessToken.split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		assertThat(cut.validate(tokenWithOthersSignature, "key-id-1", "RS256", "https://authentication.stagingaws.hanavlab.ondemand.com/token_keys" ).isValid(), is(false));
	}

	@Test
	@Ignore
	public void takePublicKeyFromCache() {
		// TODO implement
	}

	@Test
	public void validationFailsWhenTokenKeyCanNotBeRetrievedFromIdentityProvider() throws OAuth2ServiceException {
		when(serviceMock.retrieveTokenKeys(any())).thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(decodedJwt(accessToken)).isValid(), is(false));
	}

	@Test
	@Ignore
	public void validationFailsWhenTokenKeyUrlDoesNotMatchIdentityProviderDomain() {
		// TODO implement
	}

	@Test
	@Ignore
	public void requiredParameters() {
		// TODO implement
	}

	@Test
	@Ignore
	public void webTokenKeyOtherThanRSAIsNotSupported() {
		// TODO implement
	}

	private DecodedJwt decodedJwt(String token) {
		return Base64JwtDecoder.getInstance().decode(token);
	}
}
