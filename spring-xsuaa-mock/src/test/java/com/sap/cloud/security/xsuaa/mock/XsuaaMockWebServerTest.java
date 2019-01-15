package com.sap.cloud.security.xsuaa.mock;

import static org.hamcrest.Matchers.startsWith;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class XsuaaMockWebServerTest {
	private XsuaaMockWebServer xsuaaMockServer;

	@Before
	public void setUp() {
		xsuaaMockServer = new XsuaaMockWebServer();
	}

	@Test
	public void getPropertyShouldStartMockServerAndReturnUrl() {
		String url = (String) xsuaaMockServer.getProperty(XsuaaMockWebServer.MOCK_XSUAA_PROPERTY_SOURCE_NAME);
		url.replace("127.0.0.1", "localhost");
		Assert.assertThat(url, startsWith("http://localhost"));
	}
}
