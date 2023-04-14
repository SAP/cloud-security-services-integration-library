/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.net.URI;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class IdTokenSignatureValidatorTest {
	private Token iasToken;

	private JwtSignatureValidator cut;
	private OAuth2ServiceConfiguration mockConfiguration;
	private OAuth2TokenKeyService tokenKeyServiceMock;
	OAuth2ServiceEndpointsProvider endpointsProviderMock;
	private OidcConfigurationService oidcConfigurationServiceMock;
	private static final URI JKU_URI = URI.create("https://application.myauth.com/jwks_uri");
	private static final String ZONE_UUID = "0987654321";
	private static final URI DISCOVERY_URI = URI
			.create("https://application.myauth.com" + OidcConfigurationService.DISCOVERY_ENDPOINT_DEFAULT);

	@Before
	public void setup() throws IOException {
		/**
		 * Header -------- { "alg": "RS256" } Payload -------- { "iss":
		 * "https://application.myauth.com" }
		 */
		iasToken = new SapIdToken(IOUtils.resourceToString("/iasOidcTokenRSA256.txt", UTF_8));

		mockConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		when(mockConfiguration.getService()).thenReturn(Service.IAS);

		endpointsProviderMock = Mockito.mock(OAuth2ServiceEndpointsProvider.class);
		when(endpointsProviderMock.getJwksUri()).thenReturn(JKU_URI);

		oidcConfigurationServiceMock = Mockito.mock(OidcConfigurationService.class);
		when(oidcConfigurationServiceMock.retrieveEndpoints(DISCOVERY_URI))
				.thenReturn(endpointsProviderMock);

		tokenKeyServiceMock = Mockito.mock(OAuth2TokenKeyService.class);
		when(tokenKeyServiceMock
				.retrieveTokenKeys(eq(JKU_URI), eq(ZONE_UUID)))
						.thenReturn(IOUtils.resourceToString("/iasJsonWebTokenKeys.json", UTF_8));

		cut = new JwtSignatureValidator(
				mockConfiguration,
				OAuth2TokenKeyServiceWithCache.getInstance().withTokenKeyService(tokenKeyServiceMock),
				OidcConfigurationServiceWithCache.getInstance()
						.withOidcConfigurationService(oidcConfigurationServiceMock));
	}

	@Test
	public void validates_RSASignatureMatchesJWKS() {
		assertThat(cut.validate(iasToken).isValid(), is(true));
	}

	@Test
	public void validationFails_WhenEndpointProvidesNullJku() throws OAuth2ServiceException {
		when(endpointsProviderMock.getJwksUri()).thenReturn(null);

		ValidationResult result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error occurred during jwks uri determination"));
	}

	@Test
	public void validationFails_whenOAuthServerIsUnavailable_OIDC() throws OAuth2ServiceException {
		when(oidcConfigurationServiceMock
				.retrieveEndpoints(any())).thenThrow(OAuth2ServiceException.class);

		ValidationResult result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error occurred during jwks uri determination"));
	}

	@Test
	public void validationFails_whenOAuthServerIsUnavailable_JKS() throws OAuth2ServiceException {
		when(tokenKeyServiceMock
				.retrieveTokenKeys(any(), any())).thenThrow(OAuth2ServiceException.class);

		ValidationResult result = cut.validate(iasToken);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString("Error retrieving Json Web Keys from Identity Service"));
	}

	@Test
	public void validationFails_whenNoMatchingKey() throws IOException {
		ValidationResult result = cut.validate(iasToken.getTokenValue(), "RS256", "default-kid-2",
				JKU_URI.toString(), null, null);
		assertThat(result.isErroneous(), is(true));
		assertThat(result.getErrorDescription(),
				containsString(
						"There is no Json Web Token Key with keyId 'default-kid-2' and type 'RSA' found"));
	}

}
