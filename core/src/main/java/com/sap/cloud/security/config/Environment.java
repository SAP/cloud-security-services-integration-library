package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFEnvParser;
import com.sap.cloud.security.config.cf.CFOAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFService;

public class Environment {

	private static Environment instance = new Environment();
	private final SystemEnvironmentProvider systemEnvironmentProvider;
	private OAuth2ServiceConfiguration overriddenServiceConfiguration;

	private Environment() {
		this.systemEnvironmentProvider = System::getenv;
	}

	Environment(SystemEnvironmentProvider systemEnvironmentProvider) {
		this.systemEnvironmentProvider = systemEnvironmentProvider;

	}

	interface SystemEnvironmentProvider {
		String getEnv(String key);
	}

	public static Environment getInstance() {
		return instance;
	}

	public OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		if (overriddenServiceConfiguration == null) {
			return getServiceConfigurationForCurrentEnvironment();
		}
		return overriddenServiceConfiguration;
	}

	private CFOAuth2ServiceConfiguration getServiceConfigurationForCurrentEnvironment() {
		// TODO implement environment prober
		return new CFEnvParser(systemEnvironmentProvider.getEnv(CFConstants.VCAP_SERVICES)).load(CFService.XSUAA);
	}

	public void setOAuth2ServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		overriddenServiceConfiguration = serviceConfiguration;
	}

}
