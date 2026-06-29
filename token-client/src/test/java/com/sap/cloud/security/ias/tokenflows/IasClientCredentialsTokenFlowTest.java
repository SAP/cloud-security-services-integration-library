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
class IasClientCredentialsTokenFlowTest {

	private static final String IAS_BASE_URL = "https://provider.accounts.ondemand.com";
	private static final URI IAS_TOKEN_ENDPOINT = URI.create(IAS_BASE_URL + "/oauth2/token");
	private static final String ACCESS_TOKEN = "ias-access-token-abc123";

	@Mock
	private OAuth2TokenService mockTokenService;

	@Mock
	private IasTenantHostResolver mockTenantResolver;

	private ClientIdentity clientIdentity;
	private IasDefaultEndpoints endpointsProvider;
	private IasClientCredentialsTokenFlow cut;

	@BeforeEach
	void setup() {
		clientIdentity = new ClientCredentials("ias-client-id", "ias-client-secret");
		endpointsProvider = new IasDefaultEndpoints(IAS_BASE_URL);
		cut = new IasClientCredentialsTokenFlow(mockTokenService, endpointsProvider, clientIdentity, null);
	}

	@Test
	void execute_withDefaults_callsTokenService() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		OAuth2TokenResponse response = cut.execute();

		assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				eq(IAS_TOKEN_ENDPOINT),
				eq(clientIdentity),
				isNull(),
				isNull(),
				eq(Map.of()),
				eq(false));
	}

	@Test
	void execute_withAppTid_passesParameterToService() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.appTid("tenant-42").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue()).containsEntry("app_tid", "tenant-42");
	}

	@Test
	void execute_withResource_convertsToUrn() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.resource("my-target-app").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue())
				.containsEntry("resource", "urn:sap:identity:application:provider:name:my-target-app");
	}

	@Test
	void execute_withResourceUrn_passesDirectly() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.resourceUrn("urn:sap:identity:application:provider:clientid:abc123").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue())
				.containsEntry("resource", "urn:sap:identity:application:provider:clientid:abc123");
	}

	@Test
	void execute_withTokenFormat_passesParameter() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.tokenFormat("jwt").execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				any(), any(), any(), any(), paramsCaptor.capture(), anyBoolean());
		assertThat(paramsCaptor.getValue()).containsEntry("token_format", "jwt");
	}

	@Test
	void execute_withDisableCache_passesFlag() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.disableCache(true).execute();

		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				any(), any(), any(), any(), any(), eq(true));
	}

	@Test
	void execute_withTenantResolver_resolvesSubscriberEndpoint() throws TokenFlowException, OAuth2ServiceException {
		cut = new IasClientCredentialsTokenFlow(mockTokenService, endpointsProvider, clientIdentity, mockTenantResolver);
		when(mockTenantResolver.resolve("subscriber-tenant")).thenReturn("subscriber");
		mockAccessToken();

		cut.appTid("subscriber-tenant").execute();

		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				eq(URI.create("https://subscriber.accounts.ondemand.com/oauth2/token")),
				any(), any(), any(), any(), anyBoolean());
	}

	@Test
	void execute_withTenantResolver_resolverReturnsNull_usesProviderEndpoint()
			throws TokenFlowException, OAuth2ServiceException {
		cut = new IasClientCredentialsTokenFlow(mockTokenService, endpointsProvider, clientIdentity, mockTenantResolver);
		when(mockTenantResolver.resolve("unknown-tenant")).thenReturn(null);
		mockAccessToken();

		cut.appTid("unknown-tenant").execute();

		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				eq(IAS_TOKEN_ENDPOINT),
				any(), any(), any(), any(), anyBoolean());
	}

	@Test
	void execute_serviceException_throwsTokenFlowException() throws OAuth2ServiceException {
		when(mockTokenService.retrieveAccessTokenViaClientCredentialsGrant(
				any(), any(), any(), any(), any(), anyBoolean()))
				.thenThrow(new OAuth2ServiceException("401 Unauthorized"));

		assertThatThrownBy(() -> cut.execute())
				.isInstanceOf(TokenFlowException.class)
				.hasMessageContaining("IAS technical user token")
				.hasMessageContaining("401 Unauthorized");
	}

	@Test
	void execute_tenantResolverException_throwsTokenFlowException() throws OAuth2ServiceException {
		cut = new IasClientCredentialsTokenFlow(mockTokenService, endpointsProvider, clientIdentity, mockTenantResolver);
		when(mockTenantResolver.resolve("bad-tenant"))
				.thenThrow(new OAuth2ServiceException("HTTP 500"));

		assertThatThrownBy(() -> cut.appTid("bad-tenant").execute())
				.isInstanceOf(TokenFlowException.class)
				.hasMessageContaining("resolving IAS tenant host")
				.hasMessageContaining("bad-tenant");
	}

	@Test
	void execute_allParametersCombined() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.appTid("tenant-99")
				.resource("target-app")
				.tokenFormat("jwt")
				.disableCache(true)
				.execute();

		ArgumentCaptor<Map<String, String>> paramsCaptor = ArgumentCaptor.forClass(Map.class);
		verify(mockTokenService).retrieveAccessTokenViaClientCredentialsGrant(
				eq(IAS_TOKEN_ENDPOINT), eq(clientIdentity), isNull(), isNull(),
				paramsCaptor.capture(), eq(true));

		Map<String, String> params = paramsCaptor.getValue();
		assertThat(params).containsEntry("app_tid", "tenant-99");
		assertThat(params).containsEntry("resource", "urn:sap:identity:application:provider:name:target-app");
		assertThat(params).containsEntry("token_format", "jwt");
	}

	private void mockAccessToken() throws OAuth2ServiceException {
		OAuth2TokenResponse tokenResponse = new OAuth2TokenResponse(ACCESS_TOKEN, 3600, null);
		when(mockTokenService.retrieveAccessTokenViaClientCredentialsGrant(
				any(), any(), any(), any(), any(), anyBoolean()))
				.thenReturn(tokenResponse);
	}
}
