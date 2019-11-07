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

public class JwtSignatureValidatorTest {
	private Token accessToken;
	private Token otherToken; // contains alg header only, signature that does not match jwks
	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	@Before
	public void setup() throws IOException {
		accessToken = new TokenImpl(IOUtils.resourceToString("/xsuaaAccessTokenRSA256.txt", StandardCharsets.UTF_8));
		otherToken = new TokenImpl(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8));

		endpointsProvider = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProvider.getJwksUri()).thenReturn(URI.create("https://myauth.com/jwks_uri"));

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8)));

		cut = new JwtSignatureValidator(new TokenKeyServiceWithCache(tokenKeyServiceMock, endpointsProvider));
	}

	@Test
	public void validate_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			cut.validate(null, "key-id-1", "RS256");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");

		assertThatThrownBy(() -> {
			cut.validate(accessToken.getAppToken(), "", "key-id-1");
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("tokenAlgorithm");
	}

	@Test
	public void xsuaaRSASignatureMatchesJWKS() {
		assertThat(cut.validate(accessToken).isValid(), is(true));
	}

	@Test
	public void iasOidcRSASignatureMatchesJWKS() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/iasJsonWebTokenKeys.json", StandardCharsets.UTF_8)));
		assertThat(cut.validate(otherToken).isValid(), is(true));
	}

	@Test
	public void validationFails_whenJwtPayloadModified() {
		String[] tokenHeaderPayloadSignature = accessToken.getAppToken().split(Pattern.quote("."));
		String[] otherHeaderPayloadSignature = otherToken.getAppToken().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(otherHeaderPayloadSignature[1])
				.append(".")
				.append(tokenHeaderPayloadSignature[2]).toString();
		assertThat(cut.validate(new TokenImpl(tokenWithOthersSignature)).isValid(), is(false));
	}

	@Test
	public void validationFails_whenJwtProvidesNo() {
		String[] tokenHeaderPayloadSignature = accessToken.getAppToken().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		assertThat(cut.validate(tokenWithOthersSignature, "RS256", "key-id-1").isValid(), is(false));
	}

	// TODO we can move this into TokenKeyServiceWithCache
	@Test
	public void takePublicKeyFromCache() throws OAuth2ServiceException {
		cut.validate(accessToken);
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(accessToken).isValid(), is(true));
	}

	@Test
	public void validationFails_whenTokenKeyCanNotBeRetrievedFromIdentityProvider() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(accessToken).isValid(), is(false));
	}

	@Test
	public void validationFails_whenTokenKeyTypeIsNotRSA256() {
		String token = "eyJhbGciOiJFUzUxMiJ9.eyJpc3MiOiJhdXRoMCJ9.AeCJPDIsSHhwRSGZCY6rspi8zekOw0K9qYMNridP1Fu9uhrA1QrG-EUxXlE06yvmh2R7Rz0aE7kxBwrnq8L8aOBCAYAsqhzPeUvyp8fXjjgs0Eto5I0mndE2QHlgcMSFASyjHbU8wD2Rq7ZNzGQ5b2MZfpv030WGUajT-aZYWFUJHVg2";
		assertThatThrownBy(() -> {
			cut.validate(token, "ES512", "key-id-1");
		}).isInstanceOf(IllegalArgumentException.class)
				.hasMessageStartingWith("JWT token with signature algorithm ES512 can not be verified");
	}

	@Test
	@Ignore
	public void jsonECSignatureMatchesJWKS() throws IOException {
		String ecSignedToken = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
		assertThat(cut.validate(ecSignedToken, "ES256", "key-id-1").isValid(), is(true));
	}
}
