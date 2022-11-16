/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.*;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;
import java.util.regex.Pattern;

import static java.nio.charset.StandardCharsets.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class JwtSignatureValidatorTest {
	private Token iasToken;
	private Token iasPaasToken;
	private static final URI DUMMY_JKU_URI = URI.create("https://application.myauth.com/jwks_uri");

	private JwtSignatureValidator cut;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	private OAuth2ServiceConfiguration mockConfiguration;

	@Before
	public void setup() throws IOException {
		// no zone-id but iss host == jwks host
		iasPaasToken = new SapIdToken(
				"eyJraWQiOiJkZWZhdWx0LWtpZCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJQMTc2OTQ1IiwiYXVkIjoiVDAwMDMxMCIsInVzZXJfdXVpZCI6IjEyMzQ1Njc4OTAiLCJpc3MiOiJodHRwczovL2FwcGxpY2F0aW9uLm15YXV0aC5jb20iLCJleHAiOjY5NzQwMzE2MDAsImdpdmVuX25hbWUiOiJqb2huIiwiZW1haWwiOiJqb2huLmRvZUBlbWFpbC5vcmciLCJjaWQiOiJUMDAwMzEwIn0.Svrb5PriAuHOdhTFXiicr_qizHiby6b73SdovJAFnWCPDr0r8mmFoEWXjJmdLdw08daNzt8ww_r2khJ-rusUZVfiZY3kyRV1hfeChpNROGfmGbfN62KSsYBPi4dBMIGRz8SqkF6nw5nTC-HOr7Gd8mtZjG9KZYC5fKYOYRvbAZN_xyvLDzFUE6LgLmiT6fV7fHPQi5NSUfawpWQbIgK2sJjnp-ODTAijohyxQNuF4Lq1Prqzjt2QZRwvbskTcYM3gK5fgt6RYDN6MbARJIVFsb1Y7wZFg00dp2XhdFzwWoQl6BluvUL8bL73A8iJSam0csm1cuG0A7kMF9spy_whQw");
		iasToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));

		mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.IAS);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(any(), any()))
						.thenReturn(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));

		OAuth2ServiceEndpointsProvider endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(DUMMY_JKU_URI);

		OidcConfigurationService oidcConfigServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigServiceMock.retrieveEndpoints(any())).thenReturn(endpointsProviderMock);

		cut = new JwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(oidcConfigServiceMock));
	}

	@Test
	public void validate_throwsWhenTokenIsNull() {
		assertThatThrownBy(() -> {
			cut.validate(null, "RS256", "default-kid-ias", DUMMY_JKU_URI.toString(), null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("token");
	}

	@Test
	public void validate_throwsWhenAlgorithmIsNull() {
		assertThatThrownBy(() -> {
			cut.validate("eyJhbGciOiJSUzI1NiJ9", null, "default-kid-ias", DUMMY_JKU_URI.toString(), null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("tokenAlgorithm");
	}

	@Test
	public void validate_throwsWhenKeyIdIsNull() {
		assertThatThrownBy(() -> {
			cut.validate("eyJhbGciOiJSUzI1NiJ9", "RS256", "", DUMMY_JKU_URI.toString(), null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("tokenKeyId");
	}

	@Test
	public void validate_throwsWhenKeysUrlIsNull() {
		assertThatThrownBy(() -> {
			cut.validate("eyJhbGciOiJSUzI1NiJ9", "RS256", "default-kid-ias", "", null, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("tokenKeysUrl");
	}

	@Test
	public void validationFails_WhenZoneIdIsNull() {
		ValidationResult validationResult = cut.validate(iasPaasToken);
		assertTrue(validationResult.isErroneous());
		assertThat(validationResult.getErrorDescription(),
				startsWith("Error occurred during signature validation: OIDC token must provide zone_uuid."));
	}

	@Test
	public void validationFails_WhenZoneIdIsNull_ButIssuerMatchesOAuth2Url() {
		when(mockConfiguration.getUrl()).thenReturn(URI.create("https://application.myauth.com"));
		ValidationResult validationResult = cut.validate(iasPaasToken);
		assertTrue(validationResult.isValid());
	}

	@Test
	public void validate() {
		assertTrue(cut.validate(iasToken).isValid());
	}

	@Test
	public void validationFails_whenJwtPayloadModified() {
		String[] tokenHeaderPayloadSignature = iasToken.getTokenValue().split(Pattern.quote("."));
		String tokenWithOthersSignature = new StringBuilder("eyJhbGciOiJSUzI1NiJ9")
				.append(".")
				.append(tokenHeaderPayloadSignature[1])
				.append(".")
				.append(tokenHeaderPayloadSignature[2]).toString();
		assertThat(cut.validate(new SapIdToken(tokenWithOthersSignature)).isErroneous(), is(true));
	}

	@Test
	public void validationFails_whenJwtProvidesNoSignature() {
		String[] tokenHeaderPayloadSignature = iasToken.getTokenValue().split(Pattern.quote("."));
		String tokenWithNoSignature = new StringBuilder(tokenHeaderPayloadSignature[0])
				.append(".")
				.append(tokenHeaderPayloadSignature[1]).toString();

		ValidationResult result = cut.validate(tokenWithNoSignature, "RS256", "default-kid-ias",
				DUMMY_JKU_URI.toString(), null, null);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Jwt token does not consist of 'header'.'payload'.'signature'."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNotRSA256() {
		ValidationResult validationResult = cut.validate(iasToken.getTokenValue(), "ES123", "default-kid-ias",
				"https://myauth.com/jwks_uri", null, null);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm 'ES123' is not supported."));
	}

	@Test
	public void validationFails_whenTokenAlgorithmIsNone() {
		ValidationResult validationResult = cut.validate(iasToken.getTokenValue(), "NONE", "default-kid-ias",
				"https://myauth.com/jwks_uri", null, null);
		assertThat(validationResult.isErroneous(), is(true));
		assertThat(validationResult.getErrorDescription(),
				startsWith("Jwt token with signature algorithm 'NONE' is not supported."));
	}

	@Test
	public void validationFails_whenOAuthServerIsUnavailable() throws OAuth2ServiceException {
		when(tokenKeyServiceMock
				.retrieveTokenKeys(any(), any())).thenThrow(OAuth2ServiceException.class);

		ValidationResult result = cut.validate(iasToken.getTokenValue(), "RS256", "default-kid-ias",
				"http://unavailable.com/token_keys", null, null);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error retrieving Json Web Keys from Identity Service"));
	}

}
