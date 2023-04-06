/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.samples.ias;

import static com.sap.cloud.security.config.Service.IAS;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.sap.cloud.security.test.api.SecurityTestContext;
import com.sap.cloud.security.test.extension.SecurityTestExtension;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

class HelloJavaServletIntegrationTest {

	@RegisterExtension
	static SecurityTestExtension extension = SecurityTestExtension.forService(IAS)
			.useApplicationServer()
			.addApplicationServlet(HelloJavaServlet.class, HelloJavaServlet.ENDPOINT);

	private static CloseableHttpClient httpClient;
	private static SecurityTestContext rule;

	@BeforeAll
	static void setup() {
		httpClient = HttpClients.createDefault();
		rule = extension.getContext();
	}

	@AfterEach
	void clearSecurityContext() {
		SecurityContext.clear();
	}

	@AfterAll
	static void tearDown() throws IOException {
		httpClient.close();
	}

	@Test
	void requestWithoutAuthorizationHeader_unauthenticated() throws IOException {
		HttpGet request = createGetRequest(null);
		int statusCode = httpClient.execute(request, r -> r.getStatusLine().getStatusCode());
		assertThat(statusCode).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
	}

	@Test
	void requestWithEmptyAuthorizationHeader_unauthenticated() throws IOException {
		HttpGet request = createGetRequest("");
		int statusCode = httpClient.execute(request, r -> r.getStatusLine().getStatusCode());
		assertThat(statusCode).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
	}

	@Test
	void request_withValidToken() throws IOException {
		Token token = rule.getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.EMAIL, "john.doe@email.com")
				.createToken();
		HttpGet request = createGetRequest(token.getTokenValue());

		String responseBody = httpClient.execute(request, response -> {
			assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
			return IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8);
		});

		assertThat(responseBody).isEqualTo("You ('john.doe@email.com') are authenticated and can access the application.");
	}

	@Test
	void request_withInvalidToken_unauthenticated() throws IOException {
		HttpGet request = createGetRequest(rule.getPreconfiguredJwtGenerator()
				.withClaimValue(TokenClaims.ISSUER, "INVALID Issuer")
				.createToken().getTokenValue());
		int statusCode = httpClient.execute(request, r -> r.getStatusLine().getStatusCode());
		assertThat(statusCode).isEqualTo(HttpStatus.SC_UNAUTHORIZED); // 401
	}

	private HttpGet createGetRequest(String bearerToken) {
		HttpGet httpGet = new HttpGet(rule.getApplicationServerUri() + HelloJavaServlet.ENDPOINT);
		if(bearerToken != null) {
			httpGet.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
		}
		return httpGet;
	}
}