package com.sap.cloud.security.config.cf;

import static com.sap.cloud.security.config.cf.CFConstants.VCAP_SERVICES;

import javax.annotation.Nullable;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;

import java.util.Optional;
import java.util.function.Function;

public class CFEnvironment implements Environment {

	private CFEnvParser cfEnvParser;

	private final Function<String, String> systemEnvironmentProvider;
	private final Function<String, String> systemPropertiesProvider;

	public CFEnvironment() {
		systemEnvironmentProvider = System::getenv;
		systemPropertiesProvider = System::getProperty;
	}

	CFEnvironment(Function<String, String> systemEnvironmentProvider,
			Function<String, String> systemPropertiesProvider) {
		this.systemEnvironmentProvider = systemEnvironmentProvider;
		this.systemPropertiesProvider = systemPropertiesProvider;
	}

	@Override
	public OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		return getCFEnvParser().load(Service.XSUAA);
	}

	@Nullable @Override public OAuth2ServiceConfiguration getIasServiceConfiguration() {
		throw new UnsupportedOperationException("This feature is not yet active");
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
		String env = systemEnvironmentProvider.apply(VCAP_SERVICES);
		if (env == null) {
			env = systemPropertiesProvider.apply(VCAP_SERVICES);
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

}
