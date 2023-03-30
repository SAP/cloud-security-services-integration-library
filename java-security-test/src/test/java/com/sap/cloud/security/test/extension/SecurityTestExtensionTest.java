/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.extension;

import com.sap.cloud.security.test.ApplicationServerOptions;
import com.sap.cloud.security.test.api.SecurityTestContext;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.sap.cloud.security.config.Service.XSUAA;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SecurityTestExtensionTest {

	static final int PORT = 4242;
	static final int APPLICATION_SERVER_PORT = 2424;

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
	public void addingStubIsPossibleAfterSetup(SecurityTestContext context) throws IOException {
		String url = context.getWireMockServer().baseUrl() + "/testing";
		CloseableHttpClient httpClient = HttpClients.createDefault();

		context.getWireMockServer()
				.stubFor(get(urlEqualTo("/testing"))
						.willReturn(aResponse().withBody("OK")));

		try (CloseableHttpResponse response = httpClient.execute(new HttpGet(url))) {
			assertThat(response.getCode()).isEqualTo(HttpStatus.SC_OK);
			String responseBody = readBody(response);
			assertThat(responseBody).isEqualTo("OK");
		}
	}

	private String readBody(CloseableHttpResponse response) throws IOException {
		return IOUtils.toString(response.getEntity().getContent(), Charset.defaultCharset());
	}

}