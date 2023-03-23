/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import nl.altindag.log.LogCaptor;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class DefaultHttpClientFactoryTest {

	public static final HttpGet HTTP_GET = new HttpGet(java.net.URI.create("https://www.sap.com/index.html"));
	private static final ClientIdentity config = Mockito.mock(ClientIdentity.class);
	private static final ClientIdentity config2 = Mockito.mock(ClientIdentity.class);
	private final DefaultHttpClientFactory cut = new DefaultHttpClientFactory();
	private static LogCaptor logCaptor;

	@BeforeAll
	static void setup() throws IOException {
		when(config.getId()).thenReturn("theClientId");
		when(config.getKey()).thenReturn(readFromFile("/privateRSAKey.txt"));
		when(config.getCertificate()).thenReturn(readFromFile("/certificates.txt"));
		when(config.isCertificateBased()).thenCallRealMethod();

		when(config2.getId()).thenReturn("theClientId-2");
		when(config2.getKey()).thenReturn(readFromFile("/privateRSAKey.txt"));
		when(config2.getCertificate()).thenReturn(readFromFile("/certificates.txt"));
		when(config2.isCertificateBased()).thenCallRealMethod();

		logCaptor = LogCaptor.forClass(DefaultHttpClientFactory.class);
	}

	@AfterEach
	void tearDown() {
		logCaptor.clearLogs();
	}

	@Test
	void createHttpClient_sameClientId() {
		HttpClient client1 = cut.createClient(config);
		HttpClient client2 = cut.createClient(config);

		assertNotSame(client1, client2);

		assertEquals(1, cut.sslConnectionManagers.size());
	}

	@Test
	void createHttpClient_differentClientId() {
		HttpClient client1 = cut.createClient(config);
		HttpClient client2 = cut.createClient(config2);

		assertNotSame(client1, client2);

		assertEquals(2, cut.sslConnectionManagers.size());
	}

	@Test
	void closeHttpClient() throws IOException {
		CloseableHttpClient client1 = cut.createClient(config);
		HttpClient client2 = cut.createClient(config2);

		int statusCode;
		statusCode = client1.execute(HTTP_GET, HttpClientUtil.STATUS_CODE_EXTRACTOR);
		assertEquals(statusCode, HttpStatus.SC_OK);

		client1.close();

		assertThrows(IllegalStateException.class, () -> client1.execute(HTTP_GET));

		statusCode = client2.execute(HTTP_GET, HttpClientUtil.STATUS_CODE_EXTRACTOR);
		assertEquals(statusCode, HttpStatus.SC_OK);

		assertEquals(2, cut.sslConnectionManagers.size());
	}

	@Test
	@Disabled("To be fixed")
	void reuseConnections() throws IOException {
		HttpClient client = cut.createClient(config);

		for (int i = 0; i < 40; ++i) {
			int statusCode = client.execute(HTTP_GET, HttpClientUtil.STATUS_CODE_EXTRACTOR);
			assertEquals(statusCode, HttpStatus.SC_OK);
		}
	}

	@Test
	@Disabled("To be fixed")
	void assertWarnWhenCalledMoreThanOnce() {
		cut.createClient(config);
		cut.createClient(config2);
		assertThat(logCaptor.getWarnLogs()).isEmpty();

		cut.createClient(config);
		assertThat(logCaptor.getWarnLogs().get(0))
				.startsWith("Application has already created HttpClient for clientId = theClientId, please check.");

		cut.createClient(null);
		logCaptor.clearLogs();
		cut.createClient(null);
		assertThat(logCaptor.getWarnLogs()).hasSize(2);
		assertThat(logCaptor.getWarnLogs().get(0))
				.startsWith("Application has already created HttpClient for clientId = null, please check.");
	}

	private static String readFromFile(String file) throws IOException {
		return IOUtils.resourceToString(file, StandardCharsets.UTF_8);
	}

	@Test
	void disableRedirects() throws IOException {
		WireMockServer wireMockServer = new WireMockServer(8000);
		wireMockServer.stubFor(get(urlEqualTo("/redirect"))
				.willReturn(aResponse().withHeader(HttpHeaders.LOCATION, "https://sap.com")
						.withStatus(HttpStatus.SC_MOVED_PERMANENTLY)));
		wireMockServer.start();
		try {
			CloseableHttpClient client = cut.createClient(config);

			int statusCode = client.execute(new HttpGet("http://localhost:8000/redirect"), HttpClientUtil.STATUS_CODE_EXTRACTOR);
			assertEquals(statusCode, HttpStatus.SC_MOVED_PERMANENTLY);

			CloseableHttpClient client2 = cut.createClient(new ClientCredentials("client", "secret"));
			statusCode = client2.execute(new HttpGet("http://localhost:8000/redirect"), HttpClientUtil.STATUS_CODE_EXTRACTOR);
			assertEquals(statusCode, HttpStatus.SC_MOVED_PERMANENTLY);
		} finally {
			wireMockServer.stop();
		}
	}

}