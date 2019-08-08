package com.sap.cloud.security.xsuaa.token.flows;

import static org.junit.Assert.*;

import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.sap.cloud.security.xsuaa.backend.XsuaaDefaultEndpoints;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;

import com.sap.cloud.security.xsuaa.token.flows.ClientCredentialsTokenFlow;
import com.sap.cloud.security.xsuaa.token.flows.RefreshTokenFlow;
import com.sap.cloud.security.xsuaa.token.flows.UserTokenFlow;
import com.sap.cloud.security.xsuaa.token.flows.XsuaaTokenFlows;

public class XsuaaTokenFlowsTests {

	Jwt mockJwt = buildMockJwt(Arrays.asList("read", "write"));
	private XsuaaTokenFlows cut = new XsuaaTokenFlows(new RestTemplate(), new TokenDecoderMock(mockJwt), new XsuaaDefaultEndpoints("http://base/"));

	@Before
	public void setup() {
		cut = new XsuaaTokenFlows(new RestTemplate(), new TokenDecoderMock(mockJwt), new XsuaaDefaultEndpoints("http://base/"));
	}

	@Test
	public void test_startRefreshTokenFlow() {
		RefreshTokenFlow flow = cut.refreshTokenFlow();
		assertNotNull("RefreshTokenFlow must not be null.", flow);
	}

	@Test
	public void test_startUserTokenFlow() {
		UserTokenFlow flow = cut.userTokenFlow();
		assertNotNull("UserTokenFlow must not be null.", flow);
	}

	@Test
	public void test_startClientCredentialsFlow() {
		ClientCredentialsTokenFlow flow = cut.clientCredentialsTokenFlow();
		assertNotNull("ClientCredentialsTokenFlow must not be null.", flow);
	}

	private Jwt buildMockJwt(List<String> scopes) {
		Map<String, Object> jwtHeaders = new HashMap<String, Object>();
		jwtHeaders.put("dummyHeader", "dummyHeaderValue");

		Map<String, Object> jwtClaims = new HashMap<String, Object>();
		jwtClaims.put("dummyClaim", "dummyClaimValue");
		jwtClaims.put("scope", scopes);

		return new Jwt("mockJwtValue", Instant.now(), Instant.now().plusMillis(100000), jwtHeaders, jwtClaims);
	}
}
