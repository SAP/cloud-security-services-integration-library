/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Map;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class JwtBearerTokenFlowTest {

    private OAuth2TokenService tokenService;
    private OAuth2ServiceEndpointsProvider endpointsProvider;
    private JwtBearerTokenFlow cut;

    @Before
    public void setUp() {
        tokenService = mock(OAuth2TokenService.class);
        endpointsProvider = mock(OAuth2ServiceEndpointsProvider.class);

        when(endpointsProvider.getTokenEndpoint()).thenReturn(TOKEN_ENDPOINT_URI);

        cut = new JwtBearerTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS).token(ACCESS_TOKEN);
    }

    @Test
    public void tokenServiceIsNull_throwsException() {
        assertThatThrownBy(() -> new JwtBearerTokenFlow(null, endpointsProvider, CLIENT_CREDENTIALS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("OAuth2TokenService");
    }

    @Test
    public void endpointsProviderIsNull_throwsException() {
        assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, null, CLIENT_CREDENTIALS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("OAuth2ServiceEndpointsProvider");
    }

    @Test
    public void clientCredentialsAreNull_throwsException() {
        assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, endpointsProvider, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ClientIdentity");
    }

    @Test
    public void execute_bearerTokenIsMissing_throwsException() {
        assertThatThrownBy(() -> new JwtBearerTokenFlow(tokenService, endpointsProvider, CLIENT_CREDENTIALS).execute())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("bearerToken");
    }

    @Test
    public void execute_returnsCorrectAccessTokenInResponse() throws Exception {
        mockValidResponse();

        OAuth2TokenResponse actualResponse = cut.execute();

        assertThat(actualResponse.getAccessToken()).isEqualTo(JWT_BEARER_TOKEN);
    }

    @Test
    public void execute_ReturnsRefreshTokenInResponse() throws Exception {
        mockValidResponse();

        OAuth2TokenResponse actualResponse = cut.execute();

        assertThat(actualResponse.getRefreshToken()).isEqualTo(REFRESH_TOKEN);
    }

    @Test
    public void allRequiredParametersAreUsed() throws Exception {
        cut.execute();

        verify(tokenService, times(1))
                .retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(CLIENT_CREDENTIALS),
                        eq(ACCESS_TOKEN), any(), any(), eq(false));
    }

    @Test
    public void subdomainIsUsed() throws Exception {
        String newSubdomain = "staging";
        cut.subdomain(newSubdomain).execute();

        verify(tokenService, times(1))
                .retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(),
                        eq(newSubdomain), any(), anyBoolean());
    }

    @Test
    public void disableCacheIsUsed() throws Exception {
        cut.disableCache(true).execute();
        verifyThatDisableCacheIs(true);

        cut.disableCache(false).execute();
        verifyThatDisableCacheIs(false);
    }

    @Test
    public void additionalParametersAreUsed() throws Exception {
        String key = "aKey";
        String value = "aValue";
        Map<String, String> givenParameters = Maps.newHashMap(key, value);
        Map<String, String> equalParameters = Maps.newHashMap(key, value);

        cut.optionalParameters(givenParameters).execute();

        verify(tokenService, times(1))
                .retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(), eq(equalParameters), anyBoolean());
    }
    @Test
    public void execute_withScopes() throws TokenFlowException, OAuth2ServiceException {
        ArgumentCaptor<Map<String, String>> optionalParametersCaptor = ArgumentCaptor.forClass(Map.class);
        mockValidResponse();

        OAuth2TokenResponse response = cut.scopes("scope1", "scope2").execute();

        assertThat(response.getAccessToken()).isSameAs(JWT_BEARER_TOKEN);
        verify(tokenService, times(1))
                .retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(),
                        optionalParametersCaptor.capture(), anyBoolean());

        Map<String, String> optionalParameters = optionalParametersCaptor.getValue();
        assertThat(optionalParameters).containsKey("scope");
        assertThat(optionalParameters.get("scope")).isEqualTo("scope1 scope2");
    }

    @Test
    public void execute_withScopesSetToNull_throwsException() {
        assertThatThrownBy(() -> cut.scopes(null)).isInstanceOf(IllegalArgumentException.class);
    }

    private void mockValidResponse() throws OAuth2ServiceException {
        OAuth2TokenResponse validResponse = new OAuth2TokenResponse(JWT_BEARER_TOKEN, EXPIRED_IN, REFRESH_TOKEN);
        when(tokenService.retrieveAccessTokenViaJwtBearerTokenGrant(eq(TOKEN_ENDPOINT_URI), eq(CLIENT_CREDENTIALS),
                eq(ACCESS_TOKEN), any(), any() , eq(false)))
                .thenReturn(validResponse);
    }

    private void verifyThatDisableCacheIs(boolean disableCache) throws OAuth2ServiceException {
        verify(tokenService, times(1))
                .retrieveAccessTokenViaJwtBearerTokenGrant(any(), any(), any(), any(), any(), eq(disableCache));
    }
}