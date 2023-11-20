/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.webflux.xsuaa;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.ServiceConstants;
import com.sap.cloud.security.test.JwtGenerator;
import com.sap.cloud.security.spring.config.XsuaaServiceConfiguration;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.hamcrest.CoreMatchers.containsString;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureWebTestClient(timeout = "2500000")
public class TestControllerTest {

	private static WireMockServer server;
	@Autowired
	private WebTestClient webClient;

	@Autowired
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@BeforeEach
	void startWireMockServer() throws IOException {
		if(server == null) {
			server = new WireMockServer(33195);
			server.start();

			String jwksJson = IOUtils.resourceToString("/mockServer/jwks.json", StandardCharsets.UTF_8);
			server.stubFor(get(urlEqualTo("/token_keys")).willReturn(aResponse().withBody(jwksJson)));
		}
	}

	@AfterAll
	static void stopWireMockServer() {
		server.stop();
	}

	@Test
	void unauthorizedRequest() {
		//JwtGenerator jwtGenerator = new JwtGenerator("WrongClientId");
		JwtGenerator jwtGenerator = JwtGenerator.getInstance(Service.XSUAA, "WrongClientId");
		String tokenAsString = jwtGenerator.createToken().toString();

		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, tokenAsString).exchange()
				.expectStatus().isUnauthorized();
	}

	@Test
	void authorizedRequest() {
		//JwtGenerator jwtGenerator = new JwtGenerator().addScopes(getGlobalScope("Read"));
		JwtGenerator jwtGenerator = JwtGenerator.getInstance(Service.XSUAA, "TheClientId").withScopes("Read");
		String tokenAsString = jwtGenerator.createToken().toString();

		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, tokenAsString).exchange()
				.expectStatus().is2xxSuccessful().expectBody(String.class).value(containsString(",\"scope\":[\"xsapplication!t895.Read\"],"));
	}

	private String getGlobalScope(String localScope) {
		Assert.hasText(xsuaaServiceConfiguration.getProperty(ServiceConstants.XSUAA.APP_ID), "make sure that xsuaa.xsappname is configured properly.");
		return xsuaaServiceConfiguration.getProperty(ServiceConstants.XSUAA.APP_ID) + "." + localScope;
	}

}
