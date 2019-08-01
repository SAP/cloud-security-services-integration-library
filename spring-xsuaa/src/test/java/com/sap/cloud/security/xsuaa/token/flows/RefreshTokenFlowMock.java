package com.sap.cloud.security.xsuaa.token.flows;

import static org.junit.Assert.assertTrue;

import java.net.URI;

import com.sap.cloud.security.xsuaa.XsuaaDefaultEndpoints;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;

public class RefreshTokenFlowMock extends RefreshTokenFlow {

	boolean executeCalled;
	Jwt mockJwt;

	public RefreshTokenFlowMock(Jwt mockJwt) {
		super(new RestTemplate(), new NimbusTokenDecoder(), new XsuaaDefaultEndpoints(TestConstants.xsuaaBaseUri));
		this.mockJwt = mockJwt;
	}

	public RefreshTokenFlowMock(RestTemplate restTemplate, VariableKeySetUriTokenDecoder tokenDecoder,
			URI xsuaaBaseUri) {
		super(restTemplate, tokenDecoder, new XsuaaDefaultEndpoints(xsuaaBaseUri));
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
