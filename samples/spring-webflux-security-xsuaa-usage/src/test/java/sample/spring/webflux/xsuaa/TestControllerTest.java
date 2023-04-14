/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.webflux.xsuaa;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import com.sap.cloud.security.xsuaa.test.JwtGenerator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Assert;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.startsWith;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureWebTestClient(timeout = "2500000")
public class TestControllerTest {

	@Autowired
	private WebTestClient webClient;

	@Autowired
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	@Test
	public void unauthorizedRequest() {
		JwtGenerator jwtGenerator = new JwtGenerator("WrongClientId");

		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, jwtGenerator.getTokenForAuthorizationHeader()).exchange()
				.expectStatus().isUnauthorized();
	}

	@Test
	public void authorizedRequest() {
		JwtGenerator jwtGenerator = new JwtGenerator().addScopes(getGlobalScope("Read"));

		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, jwtGenerator.getTokenForAuthorizationHeader()).exchange()
				.expectStatus().is2xxSuccessful().expectBody(String.class).value(containsString(",\"scope\":[\"xsapplication!t895.Read\"],"));
	}

	private String getGlobalScope(String localScope) {
		Assert.hasText(xsuaaServiceConfiguration.getAppId(), "make sure that xsuaa.xsappname is configured properly.");
		return xsuaaServiceConfiguration.getAppId() + "." + localScope;
	}

}
