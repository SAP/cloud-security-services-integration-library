/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.TOKEN_TYPE;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.CLIENT_CREDENTIALS;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.XSUAA_BASE_URI;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaTokenFlowsTest {

	private static OAuth2ServiceConfiguration oAuth2ServiceConfiguration;
	private XsuaaTokenFlows cut;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private OAuth2TokenService oAuth2TokenService;
	private RestOperations restOperations;

	@Before
	public void setup() {
		oAuth2ServiceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(XSUAA_BASE_URI);
		this.endpointsProvider = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);
		this.restOperations = Mockito.mock(RestTemplate.class);
		Map responseMap = new HashMap<>();
		responseMap.put(ACCESS_TOKEN, "f529.dd6e30.d454677322aaabb0");
		responseMap.put(EXPIRES_IN, "43199");
		responseMap.put(TOKEN_TYPE, "bearer");
		Mockito.when(restOperations.postForEntity(any(URI.class), any(HttpEntity.class), eq(Map.class)))
				.thenReturn(new ResponseEntity<>(responseMap, HttpStatus.OK));
		this.oAuth2TokenService = new XsuaaOAuth2TokenService(restOperations);
		cut = new XsuaaTokenFlows(oAuth2TokenService, this.endpointsProvider, CLIENT_CREDENTIALS);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(null, endpointsProvider, CLIENT_CREDENTIALS);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(oAuth2TokenService, null, CLIENT_CREDENTIALS);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(oAuth2TokenService, endpointsProvider, null);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientCredentials");

	}

	@Test
	public void startRefreshTokenFlow() {
		RefreshTokenFlow flow = cut.refreshTokenFlow();
		assertNotNull("RefreshTokenFlow must not be null.", flow);
	}

	@Test
	public void startUserTokenFlow() {
		UserTokenFlow flow = cut.userTokenFlow();
		assertNotNull("UserTokenFlow must not be null.", flow);
	}

	@Test
	public void startClientCredentialsFlow() {
		ClientCredentialsTokenFlow flow = cut.clientCredentialsTokenFlow();
		assertNotNull("ClientCredentialsTokenFlow must not be null.", flow);
	}

	@Test
	public void startPasswordTokenFlow() {
		PasswordTokenFlow flow = cut.passwordTokenFlow();
		assertNotNull("PasswordTokenFlow must not be null.", flow);
	}

	@Test
	public void versionMismatch() throws TokenFlowException {
		cut = new XsuaaTokenFlows(oAuth2TokenService, this.endpointsProvider,
				new com.sap.cloud.security.xsuaa.client.ClientCredentials("sb-spring-netflix-demo!t12291",
						"2Tc2Xz7DNy4KiACwvunulmxF32w="));
		cut.clientCredentialsTokenFlow().execute();
	}

	@Test
	public void disableCaching() throws TokenFlowException {
		OAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restOperations,
				TokenCacheConfiguration.cacheDisabled());
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService,
				this.endpointsProvider, CLIENT_CREDENTIALS);
		OAuth2TokenResponse response = tokenFlows.clientCredentialsTokenFlow().execute();
		assertNotNull(response);
		assertNotEquals(response, tokenFlows.clientCredentialsTokenFlow().execute());
	}

	@Test
	public void disableCacheOnce() throws TokenFlowException {
		OAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restOperations);
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService,
				this.endpointsProvider, CLIENT_CREDENTIALS);
		OAuth2TokenResponse response = tokenFlows.clientCredentialsTokenFlow().execute();
		assertNotNull(response);
		assertNotEquals(response, tokenFlows.clientCredentialsTokenFlow()
				.disableCache(true).execute());
	}

	@Test
	public void clearCacheOnDemand() throws TokenFlowException {
		AbstractOAuth2TokenService tokenService = new XsuaaOAuth2TokenService(restOperations);
		XsuaaTokenFlows tokenFlows = new XsuaaTokenFlows(tokenService,
				this.endpointsProvider, CLIENT_CREDENTIALS);
		OAuth2TokenResponse response = tokenFlows.clientCredentialsTokenFlow().execute();
		assertNotNull(response);
		tokenService.clearCache();
		assertNotEquals(response, tokenFlows.clientCredentialsTokenFlow().execute());
	}
}
