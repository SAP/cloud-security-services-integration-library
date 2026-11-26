/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security.junitjupiter;

import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.test.RSAKeys;
import com.sap.cloud.security.test.extension.SecurityTestExtension;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static sample.spring.security.util.MockBearerTokenRequestPostProcessor.bearerToken;

@SpringBootTest
@AutoConfigureMockMvc
class TestControllerXsuaaTest {

	@RegisterExtension
	static SecurityTestExtension extension = SecurityTestExtension.forService(Service.XSUAA);

	@DynamicPropertySource
	static void mockServiceProperties(DynamicPropertyRegistry registry) {
		// A higher-priority list override replaces the list; retain both application and broker bindings.
		registry.add("sap.security.services.xsuaa[0].xsappname", () -> "xsapp!t0815");
		registry.add("sap.security.services.xsuaa[0].clientid", () -> "sb-clientId!t0815");
		registry.add("sap.security.services.xsuaa[0].clientsecret", () -> "pwd");
		registry.add("sap.security.services.xsuaa[0].plan", () -> "application");
		registry.add("sap.security.services.xsuaa[0].uaadomain", () -> extension.getContext().getWireMockServer().baseUrl());
		registry.add("sap.security.services.xsuaa[0].url", () -> extension.getContext().getWireMockServer().baseUrl());
		registry.add("sap.security.services.xsuaa[1].xsappname", () -> "xsapp!b04711");
		registry.add("sap.security.services.xsuaa[1].clientid", () -> "sb-clientId!b04711");
		registry.add("sap.security.services.xsuaa[1].plan", () -> "broker");
	}

	@Autowired
	private MockMvc mvc;

	private String jwt;

	private String brokerJwt;

	@BeforeEach
	void setup(SecurityTestContext securityTest) {
		jwt = securityTest.getPreconfiguredJwtGenerator()
				.withLocalScopes("Read")
				.createToken().getTokenValue();
		brokerJwt = securityTest.getJwtGeneratorFromFile("/broker-token.json")
				.createToken().getTokenValue();

	}

	@Test
	void sayHello() throws Exception {
		String response = mvc.perform(get("/sayHello").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("sb-clientId!t0815"));
		assertTrue(response.contains("xsapp!t0815.Read"));
	}

	@Test
	void sayHelloBroker() throws Exception {
		String response = mvc.perform(get("/sayHello").with(bearerToken(brokerJwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("sb-clientId!b04711"));
		assertTrue(response.contains("xsapp!b04711.Read"));
	}

	@Test
	void readData_OK() throws Exception {
		String response = mvc
				.perform(get("/method").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("You got the sensitive data for tenant 'the-zone-id'."));
	}

	@Test
	void readData_FORBIDDEN(SecurityTestContext securityTest) throws Exception {
		String jwtNoScopes = securityTest.getPreconfiguredJwtGenerator()
				.createToken().getTokenValue();

		mvc.perform(get("/method").with(bearerToken(jwtNoScopes)))
				.andExpect(status().isForbidden());
	}

	/**
	 * A valid signature is checked against the configured mock service, regardless of the token's unused JKU header.
	 */
	@Test
	void ignoresTokenJkuForTrustedSignature(SecurityTestContext securityTest) throws Exception {
		Token jwt = securityTest.getPreconfiguredJwtGenerator().withLocalScopes("Read")
				.withHeaderParameter(TokenHeader.JWKS_URL, "https://auth.google.com").createToken();

		mvc.perform(get("/sayHello").with(bearerToken(jwt.getTokenValue()))).andExpect(status().isOk());
	}

	@Test
	void rejectsTokenSignedWithUntrustedKey(SecurityTestContext securityTest) throws Exception {
		Token forgedToken = securityTest.getPreconfiguredJwtGenerator()
				.withLocalScopes("Read")
				.withPrivateKey(RSAKeys.generate().getPrivate())
				.createToken();

		mvc.perform(get("/sayHello").with(bearerToken(forgedToken.getTokenValue())))
				.andExpect(status().isUnauthorized());
	}
}
