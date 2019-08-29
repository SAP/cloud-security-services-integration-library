package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.client.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertNotNull;

@RunWith(MockitoJUnitRunner.class)
public class XsuaaTokenFlowsTest {

	private XsuaaTokenFlows cut;
	private ClientCredentials clientCredentials;
	private OAuth2ServiceEndpointsProvider endpointsProvider;

	@Before
	public void setup() {
		this.clientCredentials = new ClientCredentials("clientId", "clientSecret");
		this.endpointsProvider = new XsuaaDefaultEndpoints("http://base/");
		cut = new XsuaaTokenFlows(new RestTemplate(),
				this.endpointsProvider, clientCredentials);
	}

	@Test
	public void constructor_throwsOnNullValues() {
		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(null, endpointsProvider, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("RestOperations");

		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(new RestTemplate(), null, clientCredentials);
		}).isInstanceOf(IllegalArgumentException.class).hasMessageStartingWith("OAuth2ServiceEndpointsProvider");

		assertThatThrownBy(() -> {
			new XsuaaTokenFlows(new RestTemplate(), endpointsProvider, null);
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
