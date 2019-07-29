package com.sap.cloud.security.xsuaa.token.flows;

import static org.junit.Assert.assertEquals;

import java.net.URI;

import org.junit.Test;

import com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlowRequest;

public class XsuaaTokenFlowRequestTests {

	@Test
	public void test_constructor() {
		new XsuaaTokenFlowRequest(URI.create("http://token/"), URI.create("http://authz/"),
				URI.create("http://token_keys/"));
	}

	@Test
	public void test_getters() {

		URI tokenEndpointUri = URI.create("http://token/");
		URI authorizationEndpointUri = URI.create("http://authz/");
		URI tokenKeysUri = URI.create("http://token_keys/");
		String clientId = "clientId";
		String clientSecret = "clientSecret";

		XsuaaTokenFlowRequest request = new XsuaaTokenFlowRequest(tokenEndpointUri, authorizationEndpointUri,
				tokenKeysUri);
		request.setClientId(clientId);
		request.setClientSecret(clientSecret);

		assertEquals("TokenEndpointURI does not match.", request.getTokenEndpoint(), tokenEndpointUri);
		assertEquals("AuthorizationEndpointURI does not match.", request.getAuthorizeEndpoint(),
				authorizationEndpointUri);
		assertEquals("TokenKeysEndpointURI does not match.", request.getKeySetEndpoint(), tokenKeysUri);
		assertEquals("Client ID does not match", request.getClientId(), clientId);
		assertEquals("Client secret does not match", request.getClientSecret(), clientSecret);
	}
}
