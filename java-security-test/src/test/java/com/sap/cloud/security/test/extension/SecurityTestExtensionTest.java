/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.test.ApplicationServerOptions;
import com.sap.cloud.security.test.api.SecurityTestContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SecurityTestExtensionTest {

	static final int PORT = 4242;
	static final int APPLICATION_SERVER_PORT = 2424;
	private static final HttpClient httpClient = HttpClient.newHttpClient();

	@RegisterExtension
	static SecurityTestExtension securityTestExtension = SecurityTestExtension.forService(XSUAA)
			.setPort(PORT)
			.useApplicationServer(ApplicationServerOptions.forService(XSUAA).usePort(APPLICATION_SERVER_PORT));

	@Test
	void isInitializedAndStartedWithCorrectSettings() {
		SecurityTestContext context = securityTestExtension.getContext();

		assertNotNull(context);
		assertThat(context.getWireMockServer().port()).isEqualTo(PORT);
		assertThat(URI.create(context.getApplicationServerUri()).getPort())
				.isEqualTo(APPLICATION_SERVER_PORT);
	}

	@Test
	void resolveSecurityTestConfigurationParameter(SecurityTestContext context) {
		assertNotNull(context);
		assertThat(context.getWireMockServer().port()).isEqualTo(PORT);
		assertThat(URI.create(context.getApplicationServerUri()).getPort())
				.isEqualTo(APPLICATION_SERVER_PORT);
	}

	@Test
	@SuppressWarnings("deprecation")
	public void addingStubIsPossibleAfterSetup(SecurityTestContext context) throws IOException, InterruptedException {
		String url = context.getWireMockServer().baseUrl() + "/testing";

		context.getWireMockServer()
				.stubFor(get(urlEqualTo("/testing"))
						.willReturn(aResponse().withBody("OK")));

		HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(url))
				.GET()
				.build();
		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.body()).isEqualTo("OK");
	}

}