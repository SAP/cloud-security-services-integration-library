package com.sap.cloud.security.xsuaa.mock;

import static org.hamcrest.Matchers.startsWith;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class XsuaaMockWebServerTest {
	private XsuaaMockWebServer xsuaaMockServer;

	@Before
	public void setUp() {
		xsuaaMockServer = new XsuaaMockWebServer();
	}

	@Test
	public void getPropertyShouldStartMockServerAndReturnUrl() throws UnknownHostException {
		InetAddress address = InetAddress.getLocalHost();
		String url = (String) xsuaaMockServer.getProperty(XsuaaMockWebServer.MOCK_XSUAA_PROPERTY_SOURCE_NAME);
		url = url.toLowerCase();
		url = url.replace("127.0.0.1", "localhost");
		url = url.replace(address.getCanonicalHostName().toLowerCase(), "localhost");
		Assert.assertThat(url, startsWith("http://localhost"));
	}
}
