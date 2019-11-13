package com.sap.cloud.security.javasec.samples.usage;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;

import javax.annotation.Nullable;
import java.net.URI;

public class TestConfiguration implements OAuth2ServiceConfiguration {

	@Override public String getClientId() {
		return "fakeClientId";
	}

	@Override public String getClientSecret() {
		return "fakeClientSecret";
	}

	@Override public URI getUrl() {
		return URI.create("http://localhost:33195");
	}

	@Nullable @Override public String getDomain() {
		return null;
	}

	@Nullable @Override public String getProperty(String name) {
		return null;
	}

	@Override public String getServiceName() {
		return "fakeServiceNames";
	}
}
