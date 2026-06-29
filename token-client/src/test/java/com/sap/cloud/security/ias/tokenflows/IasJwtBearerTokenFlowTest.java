/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import com.sap.cloud.security.ias.client.IasDefaultEndpoints;
import com.sap.cloud.security.ias.client.IasTenantHostCacheConfiguration;
import com.sap.cloud.security.ias.client.IasTenantHostResolver;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IasJwtBearerTokenFlowTest {

	private static final String IAS_BASE_URL = "https://provider.accounts.ondemand.com";
	private static final URI IAS_TOKEN_ENDPOINT = URI.create(IAS_BASE_URL + "/oauth2/token");
	private static final String ACCESS_TOKEN = "ias-exchanged-token-xyz";
	private static final String USER_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.fake";

	@Mock
	private OAuth2TokenService mockTokenService;

	@Mock
	private IasTenantHostResolver mockTenantResolver;

	private ClientIdentity clientIdentity;
	private IasDefaultEndpoints endpointsProvider;
	private IasJwtBearerTokenFlow cut;

	@BeforeEach
	void setup() {
		clientIdentity = new ClientCredentials("ias-client-id", "ias-client-secret");
		endpointsProvider = new IasDefaultEndpoints(IAS_BASE_URL);
		cut = new IasJwtBearerTokenFlow(mockTokenService, endpointsProvider, clientIdentity, null);
	}

	@Test
	void execute_withoutToken_throwsIllegalState() {
		assertThatThrownBy(() -> cut.execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("assertion token must be set");
	}

	@Test
	void execute_withToken_callsJwtBearerGrant() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		OAuth2TokenResponse response = cut.token(USER_JWT).execute();

		assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				eq(IAS_TOKEN_ENDPOINT),
				eq(clientIdentity),
				eq(USER_JWT),
				isNull(),
				eq(Map.of()),
				eq(false));
	}

	@Test
	void execute_withAppTid_passesParameter() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.token(USER_JWT).appTid("tenant-abc").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue()).containsEntry("app_tid", "tenant-abc");
	}

	@Test
	void execute_withResource_convertsToUrn() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.token(USER_JWT).resource("target-service").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue())
				.containsEntry("resource", "urn:sap:identity:application:provider:name:target-service");
	}

	@Test
	void execute_withResourceUrn_passesDirectly() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.token(USER_JWT).resourceUrn("urn:sap:identity:application:provider:clientid:xyz").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue())
				.containsEntry("resource", "urn:sap:identity:application:provider:clientid:xyz");
	}

	@Test
	void execute_withTokenFormat_passesParameter() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.token(USER_JWT).tokenFormat("jwt").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue()).containsEntry("token_format", "jwt");
	}

	@Test
	void execute_withDisableCache_passesFlag() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.token(USER_JWT).disableCache(true).execute();

		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				any(), any(), any(), any(), any(), eq(true));
	}

	@Test
	void execute_withTenantResolver_resolvesSubscriberEndpoint() throws TokenFlowException, OAuth2ServiceException {
		cut = new IasJwtBearerTokenFlow(mockTokenService, endpointsProvider, clientIdentity, mockTenantResolver);
		when(mockTenantResolver.resolve("sub-tenant")).thenReturn("subscriber");
		mockAccessToken();

		cut.token(USER_JWT).appTid("sub-tenant").execute();

		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				eq(URI.create("https://subscriber.accounts.ondemand.com/oauth2/token")),
				any(), any(), any(), any(), anyBoolean());
	}

	@Test
	void execute_serviceException_throwsTokenFlowException() throws OAuth2ServiceException {
		when(mockTokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
				any(), any(), any(), any(), any(), anyBoolean()))
				.thenThrow(new OAuth2ServiceException("invalid_grant"));

		assertThatThrownBy(() -> cut.token(USER_JWT).execute())
				.isInstanceOf(TokenFlowException.class)
				.hasMessageContaining("IAS user token")
				.hasMessageContaining("jwt-bearer")
				.hasMessageContaining("invalid_grant");
	}

	@Test
	void execute_allParametersCombined() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.token(USER_JWT)
				.appTid("tenant-x")
				.resource("app-y")
				.tokenFormat("jwt")
				.disableCache(true)
				.execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaJwtBearerTokenGrant(
				eq(IAS_TOKEN_ENDPOINT), eq(clientIdentity), eq(USER_JWT), isNull(),
				paramsCaptor.capture(), eq(true));

		Map<String, String> params = paramsCaptor.getValue();
		assertThat(params).containsEntry("app_tid", "tenant-x");
		assertThat(params).containsEntry("resource", "urn:sap:identity:application:provider:name:app-y");
		assertThat(params).containsEntry("token_format", "jwt");
	}

	private void mockAccessToken() throws OAuth2ServiceException {
		OAuth2TokenResponse tokenResponse = new OAuth2TokenResponse(ACCESS_TOKEN, 3600, null);
		when(mockTokenService.retrieveAccessTokenViaJwtBearerTokenGrant(
				any(), any(), any(), any(), any(), anyBoolean()))
				.thenReturn(tokenResponse);
	}
}
