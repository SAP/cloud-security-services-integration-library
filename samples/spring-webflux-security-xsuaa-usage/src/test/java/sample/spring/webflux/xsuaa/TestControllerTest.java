/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.webflux.xsuaa;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.spring.token.ReactiveSecurityContext;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.extension.XsuaaExtension;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.hamcrest.CoreMatchers.containsString;

//@ExtendWith(SpringExtension.class)
@ExtendWith(XsuaaExtension.class)
@SpringBootTest
@AutoConfigureWebTestClient(timeout = "2500000")
public class TestControllerTest {

	private static final Logger logger = LoggerFactory.getLogger(ReactiveSecurityContext.class);

	private static WireMockServer server;
	@Autowired
	private WebTestClient webClient;

	@Autowired
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;
	/*private String jwtXsuaa;
	private String jwtIas;
	 */
	private String jwt;

	/*@ClassRule
	public static SecurityTestRule ruleXsuaa = SecurityTestRule.getInstance(Service.XSUAA);
	@ClassRule
	public static SecurityTestRule ruleIas = SecurityTestRule.getInstance(Service.IAS);

	 */

	@BeforeEach
	public void setUp(SecurityTestContext securityTest) {
		jwt = securityTest.getPreconfiguredJwtGenerator()
				.withLocalScopes("Read")
				.createToken().getTokenValue();





		/*jwtXsuaa = ruleXsuaa.getPreconfiguredJwtGenerator()
				.withLocalScopes("Read")
				.createToken().getTokenValue();
		jwtIas = ruleIas.getPreconfiguredJwtGenerator()
				.withClaimsFromFile("/iasClaims.json")
				.createToken().getTokenValue();

		 */
	}


	/*@BeforeEach
	void startWireMockServer() throws IOException {
		if(server == null) {
			server = new WireMockServer(33195);
			server.start();

			String jwksJson = IOUtils.resourceToString("/mockServer/jwks.json", StandardCharsets.UTF_8);
			server.stubFor(get(urlEqualTo("/token_keys")).willReturn(aResponse().withBody(jwksJson)));
		}
	}

	@AfterEach
	void stopWireMockServer() {
		server.stop();
	}

	 */


	@Test
	void unauthorizedRequest() {
		//JwtGenerator jwtGenerator = new JwtGenerator("WrongClientId");
		JwtGenerator jwtGenerator = JwtGenerator.getInstance(Service.XSUAA, "WrongClientId");
		String tokenAsString = jwtGenerator.createToken().toString();
		//String tokenAsString = jwtXsuaa.toString();

		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, jwt).exchange()
				.expectStatus().isUnauthorized();
	}

	@Test
	void authorizedRequest() {
		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt).exchange()
				//.expectStatus().isOk().expectBody(String.class).value(containsString(",\"scope\":[\"xsapplication!t895.Read\"],"));
				.expectStatus().is2xxSuccessful().expectBody(String.class).value(containsString(",\"scope\":[\"xsapplication!t895.Read\"],"));
	}

	/*
	@Test
	void sayHello() throws Exception{
		String response = mvc.perform(get("/v1/sayHello").with(bearerToken(jwt)))
				.andExpect(status().isOk())
				.andReturn().getResponse().getContentAsString();

		assertTrue(response.contains("sb-clientId!t0815"));
		assertTrue(response.contains("xsapp!t0815.Read"));
	}

	 */

	private String getGlobalScope(String localScope) {
		Assert.hasText(xsuaaServiceConfiguration.getProperty(ServiceConstants.XSUAA.APP_ID), "make sure that xsuaa.xsappname is configured properly.");
		return xsuaaServiceConfiguration.getProperty(ServiceConstants.XSUAA.APP_ID) + "." + localScope;
	}

}
