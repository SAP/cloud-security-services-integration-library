/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.webflux.hybrid;

import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.extension.IasExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.hamcrest.CoreMatchers.containsString;

@ExtendWith(IasExtension.class)
@SpringBootTest
@AutoConfigureWebTestClient(timeout = "2500000")
class TestControllerTestIas {



	@Autowired
	private WebTestClient webClient;

	private String jwt;

	@BeforeEach
	public void setUp(SecurityTestContext securityTest) {
		jwt = securityTest.getPreconfiguredJwtGenerator()
				.withClaimsFromFile("/iasClaims.json")
				.createToken().getTokenValue();
	}


	@Test
	void unauthorizedRequest() {
		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION).exchange()
				.expectStatus().isUnauthorized();
	}

	@Test
	void authorizedRequest() {
		webClient.method(HttpMethod.GET).uri("/v1/sayHello").contentType(MediaType.APPLICATION_JSON_UTF8)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt).exchange()
				.expectStatus().is2xxSuccessful().expectBody(String.class)
				.value(containsString(",\"groups\":[\"IASAUTHZ_Read\"]"))
				.value(containsString("sb-clientId!t0815"))
				.value(containsString("the-app-tid"));
	}

}
