package com.sap.cloud.security.token.validation.validators;

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
import com.sap.cloud.security.token.validation.validators.JwtSignatureValidator;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;

public class JwtSignatureValidatorTest {
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
		when(endpointsProvider.getJwksUri()).thenReturn(URI.create("https://myauth.com/jwks_uri"));

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/JSONWebTokenKeys.json", StandardCharsets.UTF_8)));

		cut = new JwtSignatureValidator(new TokenKeyServiceWithCache(tokenKeyServiceMock, endpointsProvider));
	}

	@Test
	public void jsonRSASignatureMatchesJWKS() {
		assertThat(cut.validate(token(accessToken)).isValid(), is(true));
	}

	@Test
	public void iasOIDCRSASignatureMatchesJWKS() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/iasJSONWebTokenKeys.json", StandardCharsets.UTF_8)));
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
	public void takePublicKeyFromCache() throws OAuth2ServiceException {
		cut.validate(token(accessToken));
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(token(accessToken)).isValid(), is(true));
	}

	@Test
	public void validationFailsWhenTokenKeyCanNotBeRetrievedFromIdentityProvider() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(token(accessToken)).isValid(), is(false));
	}

	@Test
	public void validationFailsWhenTokenKeyTypeIsNotRSA256() {
		String token = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2";
		assertThatThrownBy(() -> {
			cut.validate(token, "ES512", "key-id-1");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("JWT token with signature algorithm ES512 can not be verified");
	}

	@Test
	@Ignore
	public void jsonECSignatureMatchesJWKS() throws IOException {
		String ecSignedToken = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
		assertThat(cut.validate(ecSignedToken, "ES256", "key-id-1").isValid(), is(true));
	}

	private Token token(String token) {
		return new TokenImpl(Base64JwtDecoder.getInstance().decode(token));
	}
}
