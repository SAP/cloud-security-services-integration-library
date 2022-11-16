/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import static com.sap.cloud.security.xsuaa.mock.XsuaaMockWebServer.MOCK_XSUAA_DEFAULT_PORT;
import static com.sap.cloud.security.xsuaa.mock.XsuaaMockWebServer.MOCK_XSUAA_PROPERTY_SOURCE_NAME;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class XsuaaMockWebServerTest {
	XsuaaMockWebServer mockServer;

	@After
	public void shutdownServer() throws Exception {
		mockServer.destroy();
	}

	@Test
	public void getPropertyShouldStartMockServerAndReturnUrl() throws UnknownHostException {
		mockServer = new XsuaaMockWebServer(54321);
		String url = getLocalHostUrl(mockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME));

		Assert.assertThat(url, equalTo("http://localhost:54321"));
	}

	@Test
	public void startAnotherMockServerAndReturnUrl() throws Exception {
		mockServer = new XsuaaMockWebServer(12345);
		String url = getLocalHostUrl(mockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME));

		XsuaaMockWebServer otherMockServer = new XsuaaMockWebServer(23456);
		String otherUrl = getLocalHostUrl(otherMockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME));
		Assert.assertThat(otherUrl, equalTo("http://localhost:23456"));
		Assert.assertThat(otherUrl, not(url));

		otherMockServer.destroy();
	}

	@Test
	public void startMockServerAtRandomPortAndReturnUrl() throws UnknownHostException {
		mockServer = new XsuaaMockWebServer(0);
		String url = getLocalHostUrl(mockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME));

		Assert.assertThat(url, startsWith("http://localhost:"));
	}

	@Test
	public void dontStartMockServerIfAlreadyStarted() throws Exception {
		mockServer = new XsuaaMockWebServer();
		String url = getLocalHostUrl(mockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME));

		XsuaaMockWebServer mockServerSamePort = new XsuaaMockWebServer();
		String urlSame = getLocalHostUrl(mockServerSamePort.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME));

		Assert.assertThat(url, endsWith("" + MOCK_XSUAA_DEFAULT_PORT));
		Assert.assertThat(url, equalTo(urlSame));

		mockServerSamePort.destroy();
	}

	@Test
	public void restartDestroyedMockServer() throws Exception {
		mockServer = new XsuaaMockWebServer();
		mockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME); // starts the mock server
		mockServer.destroy();
		mockServer = new XsuaaMockWebServer();
		String url = getLocalHostUrl(mockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME));

		Assert.assertThat(url, endsWith("" + MOCK_XSUAA_DEFAULT_PORT));
	}

	@Test
	public void destroyWebServerOnlyIfStarted() throws Exception {
		mockServer = new XsuaaMockWebServer(4711);
		mockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME); // starts the mock server

		XsuaaMockWebServer otherMockServer = new XsuaaMockWebServer(4711);
		otherMockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME); // trys to start the mock server
		otherMockServer.destroy(); // will not shutdown

		XsuaaMockWebServer anotherMockServer = new XsuaaMockWebServer(4711);
		anotherMockServer.getProperty(MOCK_XSUAA_PROPERTY_SOURCE_NAME); // trys to start the mock server
	}

	private String getLocalHostUrl(Object urlProperty) throws UnknownHostException {
		InetAddress address = InetAddress.getLocalHost();
		String url = ((String) urlProperty).toLowerCase();
		return url.replace(address.getCanonicalHostName().toLowerCase(), "localhost");
	}
}
