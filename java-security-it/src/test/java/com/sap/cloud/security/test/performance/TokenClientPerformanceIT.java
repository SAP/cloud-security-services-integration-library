/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.performance;

import com.sap.cloud.security.client.DefaultHttpClientFactory;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.test.performance.util.BenchmarkUtil;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * Performance test for java-security jwt token validation.
 */
class TokenClientPerformanceIT {

	private static final Logger LOGGER = LoggerFactory.getLogger(TokenClientPerformanceIT.class);
	private static HttpClient client;
	private static final URI TOKENCLIENT_URL = URI.create("https://java-tokenclient-usage-((ID)).cfapps.sap.hana.ondemand.com/hello-token-client");

	@BeforeAll
	static void setUp() throws IOException {
		ClientIdentity config = Mockito.mock(ClientIdentity.class);
		when(config.getId()).thenReturn("theClientId");
		when(config.getKey()).thenReturn(readFromFile("/privateRSAKey.txt"));
		when(config.getCertificate()).thenReturn(readFromFile("/certificates.txt"));
		when(config.isCertificateBased()).thenCallRealMethod();
		client =  new DefaultHttpClientFactory().createClient(config);

		// python3 -m unittest deploy_and_test.TestTokenClient -v
		LOGGER.debug(BenchmarkUtil.getSystemInfo());
	}

	@Test
	@Disabled
	void getClientToken() throws IOException {
		HttpResponse response = client.execute(new HttpGet(TOKENCLIENT_URL));
		assertThat(response.getStatusLine().getStatusCode()).isEqualTo(HttpStatus.SC_OK);
		EntityUtils.consumeQuietly(response.getEntity());


		BenchmarkUtil.Result result = BenchmarkUtil.execute(100, 1000, () -> {
			EntityUtils.consumeQuietly(client.execute(new HttpGet(TOKENCLIENT_URL)).getEntity());
			return null;
		});
		LOGGER.info("Token client: {}", result.toString());
	}

	private static String readFromFile(String file) throws IOException {
		return IOUtils.resourceToString(file, StandardCharsets.UTF_8);
	}

}

