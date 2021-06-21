/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.CLIENT_CREDENTIALS;
import static com.sap.cloud.security.xsuaa.tokenflows.TestConstants.XSUAA_BASE_URI;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertNotNull;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaTokenFlowsTest {

	private static OAuth2ServiceConfiguration oAuth2ServiceConfiguration;
	private XsuaaTokenFlows cut;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private OAuth2TokenService oAuth2TokenService;

	@Before
	public void setup() {
		oAuth2ServiceConfiguration = Mockito.mock(OAuth2ServiceConfiguration.class);
		Mockito.when(oAuth2ServiceConfiguration.getUrl()).thenReturn(XSUAA_BASE_URI);
		this.endpointsProvider = new XsuaaDefaultEndpoints(oAuth2ServiceConfiguration);
		this.oAuth2TokenService = new XsuaaOAuth2TokenService();
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
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("ClientIdentity");

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
}
