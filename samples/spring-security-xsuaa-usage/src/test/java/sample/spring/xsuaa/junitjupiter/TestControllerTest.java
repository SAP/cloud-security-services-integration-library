/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa.junitjupiter;

import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.extension.XsuaaExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static com.sap.cloud.security.test.SecurityTest.*;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
		"xsuaa.uaadomain=" + DEFAULT_DOMAIN,
		"xsuaa.xsappname=" + DEFAULT_APP_ID,
		"xsuaa.clientid=" + DEFAULT_CLIENT_ID })
@ExtendWith(XsuaaExtension.class)
class TestControllerTest {

	@Autowired
	private MockMvc mvc;

	private String jwt;

	private String jwtAdmin;

	@BeforeEach
	public void setup(SecurityTestContext securityTest) {
		jwt = securityTest.getPreconfiguredJwtGenerator()
				.withLocalScopes("Read")
				.createToken().getTokenValue();
		jwtAdmin = securityTest.getPreconfiguredJwtGenerator()
				.withLocalScopes("Read", "Admin")
				.createToken().getTokenValue();
	}

	@Test
	void v1_sayHello() throws Exception {
		String response = mvc.perform(get("/v1/sayHello").with(bearerToken(jwtAdmin)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("sb-clientId!t0815"));
		assertTrue(response.contains("xsapp!t0815.Read"));
		assertTrue(response.contains("xsapp!t0815.Admin"));
		assertTrue(response.contains("[Read, Admin]"));
	}

	@Test
	void v2_sayHello() throws Exception {
		String response = mvc
				.perform(get("/v2/sayHello").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("Hello Jwt-Protected World!"));
	}

	@Test
	void v1_readData_OK() throws Exception {
		String response = mvc
				.perform(get("/v1/method").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("Read-protected method called!"));
	}

	@Test
	void v1_accessSensitiveData_OK() throws Exception {
		String response = mvc.perform(get("/v1/getAdminData").with(bearerToken(jwtAdmin)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("You got the sensitive data"));
	}

	@Test
	void v1_accessSensitiveData_Forbidden(SecurityTestContext securityTest) throws Exception {
		String jwtNoScopes = securityTest.getPreconfiguredJwtGenerator()
				.createToken().getTokenValue();

		mvc.perform(get("/v1/getAdminData").with(bearerToken(jwtNoScopes)))
				.andExpect(status().isForbidden());
	}

	@Test
	void v1_accessSensitiveData_unauthenticated() throws Exception {
		mvc.perform(get("/v1/getAdminData"))
				.andExpect(status().isUnauthorized());
	}

	private static class BearerTokenRequestPostProcessor implements RequestPostProcessor {
		private final String token;

		public BearerTokenRequestPostProcessor(String token) {
			this.token = token;
		}

		@Override
		public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
			request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + this.token);
			return request;
		}
	}

	private static BearerTokenRequestPostProcessor bearerToken(String token) {
		return new BearerTokenRequestPostProcessor(token);
	}
}

