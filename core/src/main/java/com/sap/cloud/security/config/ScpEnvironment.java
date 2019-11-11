package com.sap.cloud.security.config;

// TODO rename Environment
public class ScpEnvironment {

	private ScpEnvironment() {

	}

	// TODO getInstance() -> change to non-static
	// TODO check whether env needs to be specified or whether we determine it internally
	public static OAuth2ServiceConfiguration getXsuaaServiceConfiguration(String envName) {
		return null;
	}

	// TODO
	// setXsuaaServiceConfiguration(String resourceName...???)
}
