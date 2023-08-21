/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.security.junitjupiter;

import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.extension.IasExtension;
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
@ActiveProfiles("multixsuaa") // properties are provided with /resources/application-multixsuaa.yml
@ExtendWith(IasExtension.class)
class TestControllerIasTest {

	@Autowired
	private MockMvc mvc;

	private String jwt;

	@BeforeEach
	void setup(SecurityTestContext securityTest) {
		jwt = securityTest.getPreconfiguredJwtGenerator()
				.withClaimsFromFile("/iasClaims.json")
				.createToken().getTokenValue();
	}

	@Test
	void sayHello() throws Exception {
		String response = mvc.perform(get("/sayHello").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("sb-clientId!t0815"));
		assertTrue(response.contains("the-app-tid"));
	}

	@Test
	void sayHello_compatibility() throws Exception {
		mvc.perform(get("/comp/sayHello").with(bearerToken(jwt)))
				.andExpect(status().is5xxServerError());
	}

	@Test
	void readData_OK() throws Exception {
		String response = mvc
				.perform(get("/method").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("You got the sensitive data for tenant 'the-app-tid'."));
	}

	@Test
	void readData_FORBIDDEN(SecurityTestContext securityTest) throws Exception {
		String jwtNoScopes = securityTest.getPreconfiguredJwtGenerator()
				.createToken().getTokenValue();

		mvc.perform(get("/method").with(bearerToken(jwtNoScopes)))
				.andExpect(status().isForbidden());
	}
}

