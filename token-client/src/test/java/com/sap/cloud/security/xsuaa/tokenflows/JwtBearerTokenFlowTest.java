/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.client.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtBearerTokenFlowTest {

	private OAuth2TokenService mockTokenService;
	private final String exchangeToken = "exchange token";
	private final ClientIdentity clientIdentity = new ClientCredentials("clientId", "clientSecret");
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	private JwtBearerTokenFlow cut;

	@Before
	public void setup() {
		OAuth2ServiceConfiguration oAuth2ServiceConfiguration = mock(OAuth2ServiceConfiguration.class);
		when(oAuth2ServiceConfiguration.getUrl()).thenReturn(XSUAA_BASE_URI);

		this.endpointsProvider = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);
		this.mockTokenService = mock(OAuth2TokenService.class);
		this.cut = new JwtBearerTokenFlow(mockTokenService, endpointsProvider, clientIdentity);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> new JwtBearerTokenFlow(null, endpointsProvider, clientIdentity)).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> new JwtBearerTokenFlow(mockTokenService, null, clientIdentity)).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> new JwtBearerTokenFlow(mockTokenService, endpointsProvider, null)).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientIdentity");
	}

	@Test
	public void execute_throwsIfMandatoryFieldsNotSet() {
		assertThatThrownBy(cut::execute)
				.isInstanceOf(IllegalStateException.class);

		assertThatThrownBy(cut::execute)
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("A bearerToken must be set before executing the flow.");
	}

	@Test
	public void execute_throwsIfServiceRaisesException() throws OAuth2ServiceException {
		when(mockTokenService
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), isNull(), any(), anyBoolean()))
						.thenThrow(new OAuth2ServiceException("exception executed REST call"));

		assertThatThrownBy(() -> cut.token(exchangeToken).execute())
				.isInstanceOf(TokenFlowException.class)
				.hasMessageContaining(
						"Error requesting user token with grant_type 'urn:ietf:params:oauth:grant-type:jwt-bearer'");
	}

	@Test
	public void execute_callsServiceWithDefaults() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.token(exchangeToken).execute();

		assertThat(response.getAccessToken()).isSameAs(mockedResponse.getAccessToken());
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(endpointsProvider.getTokenEndpoint()),
						eq(clientIdentity), eq(exchangeToken), isNull(),
						anyMap(), eq(false));
	}

	@Test
	public void execute_withSubdomain() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();
		String subdomain = "subdomain";

		OAuth2TokenResponse response = cut.subdomain(subdomain).token(exchangeToken).execute();

		assertThat(response.getAccessToken()).isSameAs(mockedResponse.getAccessToken());

		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), eq(subdomain), any(), anyBoolean());
	}

	@Test
	public void execute_withScopes() throws TokenFlowException, OAuth2ServiceException {
		ArgumentCaptor<Map<String, String>> optionalParametersCaptor = ArgumentCaptor.forClass(Map.class);
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.scopes("scope1", "scope2").token(exchangeToken).execute();

		assertThat(response.getAccessToken()).isSameAs(mockedResponse.getAccessToken());
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(),
						optionalParametersCaptor.capture(), anyBoolean());

		Map<String, String> optionalParameters = optionalParametersCaptor.getValue();
		assertThat(optionalParameters).containsEntry("scope", "scope1 scope2");
	}

	@Test
	public void execute_withScopesSetToNull_throwsException() {
		assertThatThrownBy(() -> cut.scopes(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void execute_withDisableCache() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();

		OAuth2TokenResponse response = cut.disableCache(true).token(exchangeToken).execute();

		assertThat(response.getAccessToken()).isSameAs(mockedResponse.getAccessToken());
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(), any(), eq(true));

		cut.disableCache(false).token(exchangeToken).execute();

		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(), any(), eq(false));
	}

	 @Test
	public void execute_withAdditionalAuthorities() throws TokenFlowException, OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessToken();

		Map<String, String> additionalAuthorities = new HashMap<>();
		additionalAuthorities.put("DummyAttribute", "DummyAttributeValue");
		Map<String, String> additionalAuthoritiesParam = new HashMap<>();
		additionalAuthoritiesParam.put("authorities", "{\"az_attr\":{\"DummyAttribute\":\"DummyAttributeValue\"}}");

		OAuth2TokenResponse actualResponse = cut.token(exchangeToken)
				.attributes(additionalAuthorities)
				.execute();

		assertThat(actualResponse.getAccessToken()).isSameAs(mockedResponse.getAccessToken());
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(clientIdentity),
						eq(exchangeToken),
						isNull(), eq(additionalAuthoritiesParam), anyBoolean());
	}

	@Test
	public void execute_withZoneId() throws OAuth2ServiceException, TokenFlowException {
		String zoneId = "zone";
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessTokenWithZoneId(zoneId);

		OAuth2TokenResponse response = cut.zoneId(zoneId).token(exchangeToken).execute();

		assertThat(response.getAccessToken()).isSameAs(mockedResponse.getAccessToken());

		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), eq(exchangeToken), anyMap(), eq(false), eq(zoneId));
	}

	@Test
	public void execute_withZoneId_fromToken() throws TokenFlowException, OAuth2ServiceException {
		String zoneId = "zone-x";
		Token mockedToken = mock(Token.class);
		when(mockedToken.getTokenValue()).thenReturn(exchangeToken);
		when(mockedToken.getZoneId()).thenReturn(zoneId);
		OAuth2TokenResponse mockedResponse = mockRetrieveAccessTokenWithZoneId(zoneId);

		OAuth2TokenResponse actualResponse = cut.token(mockedToken)
				.execute();

		assertThat(actualResponse.getAccessToken()).isSameAs(mockedResponse.getAccessToken());
		verify(mockTokenService, times(1))
				.retrieveAccessTokenViaJwtBearerTokenGrant(
						eq(TOKEN_ENDPOINT_URI),
						eq(clientIdentity),
						eq(exchangeToken),
						anyMap(), anyBoolean(), eq(zoneId));
	}

	private OAuth2TokenResponse mockRetrieveAccessTokenWithZoneId(String zoneId) throws OAuth2ServiceException {
		OAuth2TokenResponse mockedResponse = new OAuth2TokenResponse("4bfad399ca10490da95c2b5eb4451d53",
				441231, REFRESH_TOKEN);
		when(mockTokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
				eq(TOKEN_ENDPOINT_URI),
				eq(clientIdentity),
				eq(exchangeToken),
				anyMap(),
				eq(false),
				eq(zoneId))
		).thenReturn(mockedResponse);

		return mockedResponse;
	}

	private OAuth2TokenResponse mockRetrieveAccessToken() throws OAuth2ServiceException {
		OAuth2TokenResponse tokenResponse = new OAuth2TokenResponse("4bfad399ca10490da95c2b5eb4451d53",
				441231, REFRESH_TOKEN);
		when(mockTokenService.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI),
				eq(clientIdentity),
				eq(exchangeToken),
				any(), any(), anyBoolean()))
						.thenReturn(tokenResponse);
		return tokenResponse;
	}

}