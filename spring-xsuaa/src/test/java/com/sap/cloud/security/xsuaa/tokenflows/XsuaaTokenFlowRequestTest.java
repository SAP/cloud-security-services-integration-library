package com.sap.cloud.security.xsuaa.tokenflows;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.net.URI;

import org.junit.Test;

public class XsuaaTokenFlowRequestTest {

	@Test
	public void initialize() {
		XsuaaTokenFlowRequest request = new XsuaaTokenFlowRequest(URI.create("https://oauth.server.com/oauth/token"));
		String clientId = "clientId";
		String clientSecret = "clientSecret";

		request.setClientId(clientId);
		request.setClientSecret(clientSecret);

		assertThat(request.getTokenEndpoint().toString(), is("https://oauth.server.com/oauth/token"));
		assertThat(request.getClientId(), is(clientId));
		assertThat(request.getClientSecret(), is(clientSecret));
	}
}
