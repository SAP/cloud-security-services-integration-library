package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFEnvParser;
import com.sap.cloud.security.config.cf.CFOAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFService;

// TODO this class is a central access point to read/ get the configuration.
// In production it would be okay, to parse VCAP_SERVICES once at application start. But we can not guarantee, that
// People cache the result themselves....
// So, we have to make sure that it can be called more than one time without parsing it again.
public class Environment {
	enum Type {
		CF, KUBERNETES;

		public static Type from(String typeAsString) {
			return Type.valueOf(typeAsString.toUpperCase());
		}
	}

	private Type type;
	private static Environment instance = new Environment();
	private final SystemEnvironmentProvider systemEnvironmentProvider;
	private OAuth2ServiceConfiguration overriddenServiceConfiguration; // TODO what's the purpose of this? Testing?

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

	public int getNumberOfXsuaaServices() {
		return 1; // TODO implement
		//return envParser.loadAll(CFService.XSUAA).size();
	}

	/**
	 * In case there is only one binding, this gets returned.
	 * In case there are multiple bindings the one of plan "broker" gets returned.
	 * @return the service configuration to be used for token exchange {@link com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows}
	 */
	public OAuth2ServiceConfiguration getXsuaaServiceConfigurationForTokenExchange() {
		return null; // TODO implement
		// if getNumberOfXsuaaServices() > 1
		// return envParser.loadServiceByPlan(CFService.XSUAA, CFConstants.Plan.BROKER).size();
	}


	public Type getType() {
		if(type == null) {
			// TODO implement and test
			type = Type.CF;
		}
		return type;
	}

	private CFOAuth2ServiceConfiguration getServiceConfigurationForCurrentEnvironment() {
		if (Type.CF.equals(getType())) {
			return new CFEnvParser(systemEnvironmentProvider.getEnv(CFConstants.VCAP_SERVICES)).load(CFService.XSUAA);
		}
		return null; // No other environement supported as of now
	}

	public void setOAuth2ServiceConfiguration(OAuth2ServiceConfiguration serviceConfiguration) {
		overriddenServiceConfiguration = serviceConfiguration;
	}

}
