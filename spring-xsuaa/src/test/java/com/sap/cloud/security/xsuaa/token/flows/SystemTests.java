package com.sap.cloud.security.xsuaa.token.flows;

import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.token.flows.ClientCredentialsTokenFlow;
import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.TokenFlowException;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;

public class SystemTests {

	private static final Logger logger = LoggerFactory.getLogger(SystemTests.class);
	private RestTemplate restTemplate;
	private VariableKeySetUriTokenDecoder tokenDecoder;

	@Before
	public void setup() {
		this.restTemplate = new RestTemplate();
		this.tokenDecoder = new NimbusTokenDecoder();
	}

	@Test
	public void test_clientCredentialsFlow_withBaseURI() throws TokenFlowException {
		ClientCredentialsTokenFlow tokenFlow = new ClientCredentialsTokenFlow(restTemplate, tokenDecoder,
				TestConstants.xsuaaBaseUri);
		Jwt clientCredentialsToken = tokenFlow.client(TestConstants.clientId)
				.secret(TestConstants.clientSecret)
				.execute();

		logger.info("Received Client Credentials Token: {}", clientCredentialsToken.getTokenValue());

		assertNotNull("Token must not be null.", clientCredentialsToken);
		assertNotNull("Token value must not be null.", clientCredentialsToken.getTokenValue());
	}

	@Test
	public void test_clientCredentialsFlow_withEndpointURIs() throws TokenFlowException {
		ClientCredentialsTokenFlow tokenFlow = new ClientCredentialsTokenFlow(restTemplate, tokenDecoder,
				TestConstants.tokenEndpointUri, TestConstants.authorizeEndpointUri, TestConstants.keySetEndpointUri);
		Jwt clientCredentialsToken = tokenFlow.client(TestConstants.clientId)
				.secret(TestConstants.clientSecret)
				.execute();

		logger.info("Received Client Credentials Token: {}", clientCredentialsToken.getTokenValue());

		assertNotNull("Token must not be null.", clientCredentialsToken);
		assertNotNull("Token value must not be null.", clientCredentialsToken.getTokenValue());
	}
}
