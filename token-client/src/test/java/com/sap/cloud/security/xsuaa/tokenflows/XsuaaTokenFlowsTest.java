package com.sap.cloud.security.xsuaa.tokenflows;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertNotNull;

import com.sap.cloud.security.xsuaa.client.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.web.client.RestTemplate;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaTokenFlowsTest {

	private XsuaaTokenFlows cut;
	private ClientCredentials clientCredentials;
	private OAuth2ServiceEndpointsProvider endpointsProvider;
	private OAuth2TokenService oAuth2TokenService;

	@Before
	public void setup() {
		this.clientCredentials = new ClientCredentials("clientId", "clientSecret");
		this.endpointsProvider = new XsuaaDefaultEndpoints("http://base/");
		this.oAuth2TokenService = new XsuaaOAuth2TokenService(new RestTemplate());
		cut = new XsuaaTokenFlows(oAuth2TokenService, this.endpointsProvider, clientCredentials);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(null, endpointsProvider, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2TokenService");

		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(oAuth2TokenService, null, clientCredentials);
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
}
