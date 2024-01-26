/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security.junitjupiter;

import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.extension.XsuaaExtension;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenHeader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static sample.spring.security.util.MockBearerTokenRequestPostProcessor.bearerToken;

@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(XsuaaExtension.class)
@ActiveProfiles("multixsuaa") // properties are provided with /resources/application-multixsuaa.yml
class TestControllerXsuaaTest {

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
	void sayHello_compatibility() throws Exception {
		String response = mvc.perform(get("/comp/sayHello").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("sb-clientId!t0815"));
		assertTrue(response.contains("xsapp!t0815.Read"));
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
	 * Ensures that tokens with a JKU whose domain differs from the
	 * {@link com.sap.cloud.security.config.ServiceConstants.XSUAA#UAA_DOMAIN} in the credentials are still not trusted,
	 * even when java-security-test supplies {@link com.sap.cloud.security.token.validation.XsuaaJkuFactory}, which
	 * trusts JKUs from tokens targeting localhost.
	 */
	@Test
	void acceptsOnlyLocalhostJku(SecurityTestContext securityTest) throws Exception {
		Token jwt = securityTest.getPreconfiguredJwtGenerator().withLocalScopes("Read")
				.withHeaderParameter(TokenHeader.JWKS_URL, "https://auth.google.com").createToken();

		mvc.perform(get("/sayHello").with(bearerToken(jwt.getTokenValue()))).andExpect(status().isUnauthorized());
	}
}

