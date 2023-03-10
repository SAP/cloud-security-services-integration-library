package com.sap.cloud.security.xsuaa;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import okhttp3.mockwebserver.MockWebServer;

@TestConfiguration
public class MockXsuaaServerConfiguration {

	@Bean
	@Primary
	public MockWebServer xsuaaMockWebServer() {
		MockWebServer server = new MockWebServer();
		server.setDispatcher(new XsuaaRequestDispatcher());
		return server;
	}

	@Bean
	@Primary
	public XsuaaServiceConfiguration xsuaaServiceConfiguration(MockWebServer mockServer) {
		return new XsuaaServiceConfigurationDefault() {
			@Override
			public String getUaaDomain() {
				String mockServerUrl = mockServer.url("").toString();
				if (!mockServerUrl.isEmpty()) {
					return "localhost";
				}
				return super.getUaaDomain();
			}

			@Override
			public String getUaaUrl() {
				String mockServerUrl = mockServer.url("").toString();
				if (!mockServerUrl.isEmpty()) {
					return mockServerUrl;
				}
				return super.getUaaUrl();
			}
		};
	}

}
