package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class JwtSignatureValidatorTest {
	private Token xsuaaToken;
	private Token iasToken; // contains alg header only, signature that does not match jwks
	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceEndpointsProvider endpointsProviderMock;
	private OidcConfigurationService oidcConfigurationServiceMock;

	@Before
	public void setup() throws IOException {
		xsuaaToken = new XsuaaToken(IOUtils.resourceToString("/xsuaaCCAccessTokenRSA256.txt", StandardCharsets.UTF_8));
		iasToken = new IasToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", StandardCharsets.UTF_8));

		endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(URI.create("https://myauth.com/jwks_uri"));

		oidcConfigurationServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigurationServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(any()))
						.thenReturn(JsonWebKeySetFactory.createFromJson(
								IOUtils.resourceToString("/jsonWebTokenKeys.json", StandardCharsets.UTF_8)));

		cut = new JwtSignatureValidator(
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(oidcConfigurationServiceMock));
	}

	@Test
	public void validate_throwsWhenTokenIsNull() {
		assertThatThrownBy(() -> {
			cut.validate(null, "key-id-1", "RS256", null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test
	public void xsuaaRSASignatureMatchesJWKS() {
		assertThat(cut.validate(xsuaaToken).isValid(), is(true));
	}

	@Test
	public void iasOidcRSASignatureMatchesJWKS() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/iasJsonWebTokenKeys.json", StandardCharsets.UTF_8)));
		assertThat(cut.validate(iasToken).isValid(), is(true));
	}

	@Test
	public void validationFails_whenJwtPayloadModified() {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getAccessToken().split(Pattern.quote("."));
		String[] otherHeaderPayloadSignature = iasToken.getAccessToken().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(otherHeaderPayloadSignature[1])
				.append(".")
				.append(tokenHeaderPayloadSignature[2]).toString();
		assertThat(cut.validate(new XsuaaToken(tokenWithOthersSignature)).isErroneous(), is(true));
	}

	@Test
	public void validationFails_whenJwtProvidesNoSignature() throws IOException {
		String[] tokenHeaderPayloadSignature = xsuaaToken.getAccessToken().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		ValidationResult result = cut.validate(tokenWithOthersSignature, "RS256", "key-id-1",
				"https://myauth.com/jwks_uri");
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Jwt token does not consist of 'header'.'payload'.'signature'."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNotRSA256() {
		ValidationResult validationResult = cut.validate(xsuaaToken.getAccessToken(), "ES123", "key-id-1",
				"https://myauth.com/jwks_uri");
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm 'ES123' can not be verified."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNull() {
		ValidationResult validationResult = cut.validate(xsuaaToken.getAccessToken(), "", "key-id-1",
				"https://myauth.com/jwks_uri");
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm '' can not be verified."));
	}

	@Test
	@Ignore
	public void jsonECSignatureMatchesJWKS() {
		String ecSignedToken = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.4iVk3-Y0v4RT4_9IaQlp-8dZ_4fsTzIylgrPTDLrEvTHBTyVS3tgPbr2_IZfLETtiKRqCg0aQ5sh9eIsTTwB1g";
		assertThat(cut.validate(ecSignedToken, "ES256", "key-id-1", null).isValid(), is(true));
	}

	// TODO we can move this into TokenKeyServiceWithCache
	@Test
	public void takePublicKeyFromCache() throws OAuth2ServiceException {
		cut.validate(xsuaaToken);
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(xsuaaToken).isValid(), is(true));
	}

	@Test
	public void validationFails_whenTokenKeyCanNotBeRetrievedFromIdentityProvider() throws OAuth2ServiceException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));
		ValidationResult validationResult = cut.validate(xsuaaToken);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Error retrieving Json Web Keys from Identity Service: Currently unavailable."));
	}

	// TODO we can move this into OidcConfigurationServiceWithCache
	@Test
	public void takeOidcEndpointsProviderFromCache() throws IOException {
		when(tokenKeyServiceMock.retrieveTokenKeys(any())).thenReturn(JsonWebKeySetFactory.createFromJson(
				IOUtils.resourceToString("/iasJsonWebTokenKeys.json", StandardCharsets.UTF_8)));
		cut.validate(iasToken);
		when(oidcConfigurationServiceMock.retrieveEndpoints(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));
		assertThat(cut.validate(iasToken).isValid(), is(true));
	}

	@Test
	public void validationFails_whenOidcConfigurationCanNotBeRetrievedFromIdentityProvider()
			throws OAuth2ServiceException {
		when(oidcConfigurationServiceMock.retrieveEndpoints(any()))
				.thenThrow(new OAuth2ServiceException("Currently unavailable"));
		ValidationResult validationResult = cut.validate(iasToken);
		assertThat(validationResult.isValid(), is(false));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Error occurred during jwks uri determination: Currently unavailable."));
	}

}
