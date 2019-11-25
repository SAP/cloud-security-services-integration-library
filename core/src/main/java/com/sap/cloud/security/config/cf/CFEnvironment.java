package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;

import java.util.Optional;

public class CFEnvironment implements Environment {

	private CFEnvParser cfEnvParser;

	private final SystemEnvironmentProvider systemEnvironmentProvider;
	private final SystemPropertiesProvider systemPropertiesProvider;

	public CFEnvironment() {
		systemEnvironmentProvider = System::getenv;
		systemPropertiesProvider = System::getProperty;
	}

	CFEnvironment(SystemEnvironmentProvider systemEnvironmentProvider,
			SystemPropertiesProvider systemPropertiesProvider) {
		this.systemEnvironmentProvider = systemEnvironmentProvider;
		this.systemPropertiesProvider = systemPropertiesProvider;
	}

	@Override
	public OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		return getCFEnvParser().load(Service.XSUAA);
	}

	@Override
	public int getNumberOfXsuaaServices() {
		return getCFEnvParser().loadAll(Service.XSUAA).size();
	}

	@Override
	public OAuth2ServiceConfiguration getXsuaaServiceConfigurationForTokenExchange() {
		if (getNumberOfXsuaaServices() > 1) {
			return getCFEnvParser().loadByPlan(Service.XSUAA, CFConstants.Plan.BROKER);
		}
		return getXsuaaServiceConfiguration();
	}

	@Override
	public Type getType() {
		return Type.CF;
	}

	private Optional<String> extractVcapJsonString() {
		String env = systemEnvironmentProvider.getEnv(CFConstants.VCAP_SERVICES);
		if (env == null) {
			env = systemPropertiesProvider.getProperty(CFConstants.VCAP_SERVICES);
		}
		return Optional.ofNullable(env);
	}

	private CFEnvParser getCFEnvParser() {
		if (cfEnvParser == null) {
			cfEnvParser = extractVcapJsonString()
					.map(vcapString -> new CFEnvParser(vcapString))
					.orElse(new CFEnvParser("{}")); // no data
		}
		return cfEnvParser;
	}

	interface SystemEnvironmentProvider {
		String getEnv(String key);
	}

	interface SystemPropertiesProvider {
		String getProperty(String key);
	}

}
