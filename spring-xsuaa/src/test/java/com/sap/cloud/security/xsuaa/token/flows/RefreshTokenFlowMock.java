package com.sap.cloud.security.xsuaa.token.flows;

import static org.junit.Assert.assertTrue;

import java.net.URI;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.token.flows.NimbusTokenDecoder;
import com.sap.cloud.security.xsuaa.token.flows.RefreshTokenFlow;
import com.sap.cloud.security.xsuaa.token.flows.TokenFlowException;
import com.sap.cloud.security.xsuaa.token.flows.VariableKeySetUriTokenDecoder;

public class RefreshTokenFlowMock extends RefreshTokenFlow {

	boolean executeCalled;
	Jwt mockJwt;

	public RefreshTokenFlowMock(Jwt mockJwt) {
		super(new RestTemplate(), new NimbusTokenDecoder(), TestConstants.xsuaaBaseUri);
		this.mockJwt = mockJwt;
	}

	public RefreshTokenFlowMock(RestTemplate restTemplate, VariableKeySetUriTokenDecoder tokenDecoder,
			URI xsuaaBaseUri) {
		super(restTemplate, tokenDecoder, xsuaaBaseUri);
	}

	public RefreshTokenFlowMock(RestTemplate restTemplate, VariableKeySetUriTokenDecoder tokenDecoder,
			URI tokenEndpoint, URI authorizeEndpoint, URI keySetEndpoint) {
		super(restTemplate, tokenDecoder, tokenEndpoint, authorizeEndpoint, keySetEndpoint);
	}

	@Override
	public Jwt execute() throws TokenFlowException {
		executeCalled = true;
		return mockJwt;
	}

	public void validateCallstate() {
		assertTrue("RefreshTokenFlow's execute() method was not called. Must be called to fetch token.", executeCalled);
	}
}
