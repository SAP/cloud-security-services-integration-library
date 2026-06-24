/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IasRefreshTokenFlowTest {

	private static final String IAS_BASE_URL = "https://provider.accounts.ondemand.com";
	private static final URI IAS_TOKEN_ENDPOINT = URI.create(IAS_BASE_URL + "/oauth2/token");
	private static final URI SUBSCRIBER_TOKEN_ENDPOINT = URI.create(
			"https://subscriber.accounts.ondemand.com/oauth2/token");
	private static final String REFRESH_TOKEN = "ias-refresh-token-xyz";
	private static final String ACCESS_TOKEN = "ias-access-token-abc123";

	@Mock
	private OAuth2TokenService mockTokenService;

	@Mock
	private IasTenantHostResolver mockTenantResolver;

	private ClientIdentity clientIdentity;
	private IasDefaultEndpoints endpointsProvider;
	private IasRefreshTokenFlow cut;

	@BeforeEach
	void setup() {
		clientIdentity = new ClientCredentials("ias-client-id", "ias-client-secret");
		endpointsProvider = new IasDefaultEndpoints(IAS_BASE_URL);
		cut = new IasRefreshTokenFlow(mockTokenService, endpointsProvider, clientIdentity, null);
	}

	@Test
	void execute_withRefreshToken_callsTokenService() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		OAuth2TokenResponse response = cut.refreshToken(REFRESH_TOKEN).execute();

		assertThat(response.getAccessToken()).isEqualTo(ACCESS_TOKEN);
		verify(mockTokenService).retrieveAccessTokenViaRefreshToken(
				eq(IAS_TOKEN_ENDPOINT),
				eq(clientIdentity),
				eq(REFRESH_TOKEN),
				isNull(),
				eq(false));
	}

	@Test
	void execute_withoutRefreshToken_throwsIllegalState() {
		assertThatThrownBy(() -> cut.execute())
				.isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("Refresh token not set");
	}

	@Test
	void execute_withDisableCache_passesFlag() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.refreshToken(REFRESH_TOKEN).disableCache(true).execute();

		verify(mockTokenService).retrieveAccessTokenViaRefreshToken(
				any(), any(), any(), any(), eq(true));
	}

	@Test
	void execute_withTenantResolver_resolvesSubscriberEndpoint() throws TokenFlowException, OAuth2ServiceException {
		cut = new IasRefreshTokenFlow(mockTokenService, endpointsProvider, clientIdentity, mockTenantResolver);
		when(mockTenantResolver.resolve("subscriber-tenant")).thenReturn("subscriber");
		mockAccessToken();

		cut.refreshToken(REFRESH_TOKEN).appTid("subscriber-tenant").execute();

		verify(mockTokenService).retrieveAccessTokenViaRefreshToken(
				eq(SUBSCRIBER_TOKEN_ENDPOINT),
				any(), any(), any(), anyBoolean());
	}

	@Test
	void execute_withAppTidButNoResolver_usesProviderEndpoint() throws TokenFlowException, OAuth2ServiceException {
		mockAccessToken();

		cut.refreshToken(REFRESH_TOKEN).appTid("subscriber-tenant").execute();

		verify(mockTokenService).retrieveAccessTokenViaRefreshToken(
				eq(IAS_TOKEN_ENDPOINT),
				any(), any(), any(), anyBoolean());
	}

	@Test
	void execute_tokenServiceThrows_isWrappedInTokenFlowException() throws OAuth2ServiceException {
		when(mockTokenService.retrieveAccessTokenViaRefreshToken(any(), any(), any(), any(), anyBoolean()))
				.thenThrow(new OAuth2ServiceException("boom"));

		assertThatThrownBy(() -> cut.refreshToken(REFRESH_TOKEN).execute())
				.isInstanceOf(TokenFlowException.class)
				.hasMessageContaining("grant_type 'refresh_token'");
	}

	@Test
	void execute_resolverThrows_isWrappedInTokenFlowException() throws OAuth2ServiceException {
		cut = new IasRefreshTokenFlow(mockTokenService, endpointsProvider, clientIdentity, mockTenantResolver);
		when(mockTenantResolver.resolve("subscriber-tenant"))
				.thenThrow(new OAuth2ServiceException("BTP API failed"));

		assertThatThrownBy(() -> cut.refreshToken(REFRESH_TOKEN).appTid("subscriber-tenant").execute())
				.isInstanceOf(TokenFlowException.class)
				.hasMessageContaining("Error resolving IAS tenant host");
	}

	private void mockAccessToken() throws OAuth2ServiceException {
		OAuth2TokenResponse mockResponse = new OAuth2TokenResponse(ACCESS_TOKEN, 3600L, null);
		when(mockTokenService.retrieveAccessTokenViaRefreshToken(any(), any(), any(), any(), anyBoolean()))
				.thenReturn(mockResponse);
	}
}