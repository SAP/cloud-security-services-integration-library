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

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
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
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	@Before
	public void setup() throws IOException {
		accessToken = IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8);
		otherToken = IOUtils.resourceToString("/iasOIDCTokenAlgHeaderOnly.txt", StandardCharsets.UTF_8);

		endpointsProvider = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProvider.getJwksUri()).thenReturn(URI.create("https://authentication.stagingaws.hanavlab.ondemand.com/token_keys"));
		//when(serviceConfigurationMock.getUaaDomain()).thenReturn("stagingaws.hanavlab.ondemand.com");

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenReturn(createJSONWebKeySet());

		cut = new JwtSignatureValidator(tokenKeyServiceMock, endpointsProvider);
	}

	private JSONWebKeySet createJSONWebKeySet() {
		JSONWebKey jsonWebKey = new JSONWebKeyImpl(
				JSONWebKey.Type.RSA, "key-id-1", "RS256", pemEncodedPublicKey);
		JSONWebKey jsonWebKeyDefault = new JSONWebKeyImpl(
				JSONWebKey.Type.RSA, JSONWebKey.DEFAULT_KEY_ID, "RS256", null);

		JSONWebKeySet keySet = new JSONWebKeySet();
		keySet.put(jsonWebKey);
		keySet.put(jsonWebKeyDefault);
		return keySet;
	}

	@Test
	public void jsonWebSignatureMatchesJWKS() {
		assertThat(cut.validate(token(accessToken)).isValid(), is(true));
	}

	@Test
	@Ignore // TODO
	public void iasOIDCSignatureMatchesJWKS() {
		cut = new JwtSignatureValidator(tokenKeyServiceMock, URI.create("https://xs2security.accounts400.ondemand.com/oauth2/certs"));
		assertThat(cut.validate(token(otherToken)).isValid(), is(true));
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
		assertThat(cut.validate(token(tokenWithOthersSignature)).isValid(), is(false));
	}


	@Test
	public void validate_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.validate(null, "key-id-1", "RS256");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");

		assertThatThrownBy(() -> {
			cut.validate(accessToken, "", "key-id-1" );
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenAlgorithm");
	}

	@Test
	public void jwtWithoutSignatureNotValid() {
		String[] tokenHeaderPayloadSignature = accessToken.split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		assertThat(cut.validate(tokenWithOthersSignature, "RS256","key-id-1" ).isValid(), is(false));
	}

	@Test
	@Ignore
	public void takePublicKeyFromCache() {
		// TODO implement
	}

	@Test
	public void validationFailsWhenTokenKeyCanNotBeRetrievedFromIdentityProvider() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(token(accessToken)).isValid(), is(false));
	}

	@Test
	@Ignore
	public void webTokenKeyOtherThanRSAIsNotSupported() {
		// TODO implement
	}

	private Token token(String token) {
		DecodedJwt decodedJwt = Base64JwtDecoder.getInstance().decode(token);
		return new TokenImpl(decodedJwt.getHeader(), decodedJwt.getPayload(), decodedJwt.getEncodedToken());
	}

}
