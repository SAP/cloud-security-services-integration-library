package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;

import javax.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class TestConfiguration implements OAuth2ServiceConfiguration {

	private final Map<String, String> properties = new HashMap<>();

	public TestConfiguration() {
		properties.put(CFConstants.XSUAA.APP_ID, "fakeAppId");
	}

	@Override public String getClientId() {
		return "sb-clientId!20";
	}

	@Override public String getClientSecret() {
		return "fakeClientSecret";
	}

	@Override public URI getUrl() {
		return URI.create("http://localhost:33195");
	}

	@Nullable @Override public String getDomain() {
		return "localhost";
	}

	@Nullable @Override public String getProperty(String name) {
		return properties.get(name);
	}

	@Override public String getServiceName() {
		return "xsuaa";
	}
}
