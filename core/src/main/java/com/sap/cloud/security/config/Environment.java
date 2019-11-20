package com.sap.cloud.security.config;

import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.config.cf.CFEnvParser;
import com.sap.cloud.security.config.cf.CFService;
import com.sun.tools.internal.xjc.model.CEnumConstant;

import java.util.Optional;

// TODO this class is a central access point to read/ get the configuration.
// In production it would be okay, to parse VCAP_SERVICES once at application start. But we can not guarantee, that
// People cache the result themselves....
// So, we have to make sure that it can be called more than one time without parsing it again.
public class Environment {

	private CFEnvParser cfEnvParser;

	enum Type {
		CF, KUBERNETES;
		public static Type from(String typeAsString) {
			return Type.valueOf(typeAsString.toUpperCase());
		}
	}

	private Type type;
	private static Environment instance = new Environment();
	private final SystemEnvironmentProvider systemEnvironmentProvider;
	private final SystemPropertiesProvider systemPropertiesProvider;

	private Environment() {
		systemEnvironmentProvider = System::getenv;
		systemPropertiesProvider = System::getProperty;
	}

	Environment(SystemEnvironmentProvider systemEnvironmentProvider,
			SystemPropertiesProvider systemPropertiesProvider) {
		this.systemEnvironmentProvider = systemEnvironmentProvider;
		this.systemPropertiesProvider = systemPropertiesProvider;
	}

	interface SystemEnvironmentProvider {
		String getEnv(String key);
	}

	interface SystemPropertiesProvider {
		String getProperty(String key);
	}

	public static Environment getInstance() {
		return instance;
	}

	public OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		if (cfEnvParser == null && Type.CF == getType()) {
			cfEnvParser = extractVcapJsonString()
					.map(vcapString -> new CFEnvParser(vcapString))
					.orElse(null);
			return cfEnvParser == null ? null : cfEnvParser.load(CFService.XSUAA);
		}
		return null; // No other environement supported as of now
	}

	/**
	 * @deprecated as multiple bindings of identity service is not anymore necessary
	 *             with the unified broker plan, this method is deprecated.
	 */
	@Deprecated
	public int getNumberOfXsuaaServices() {
		return cfEnvParser.loadAll(CFService.XSUAA).size();
	}

	/**
	 * In case there is only one binding, this gets returned. In case there are
	 * multiple bindings the one of plan "broker" gets returned.
	 * 
	 * @return the service configuration to be used for token exchange
	 *         {@link com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows}
	 * @deprecated as multiple bindings of identity service is not anymore necessary
	 *             with the unified broker plan, this method is deprecated.
	 */
	@Deprecated
	public OAuth2ServiceConfiguration getXsuaaServiceConfigurationForTokenExchange() {
		if (getNumberOfXsuaaServices() > 1) {
			return cfEnvParser.loadByPlan(CFService.XSUAA, CFConstants.Plan.BROKER);
		}
		return getXsuaaServiceConfiguration();
	}

	public Type getType() {
		if (type == null) {
			// TODO implement and test
			type = Type.CF;
		}
		return type;
	}

	private Optional<String> extractVcapJsonString() {
		String env = systemEnvironmentProvider.getEnv(CFConstants.VCAP_SERVICES);
		if (env == null) {
			env = systemPropertiesProvider.getProperty(CFConstants.VCAP_SERVICES);
		}
		return Optional.ofNullable(env);

	}

}
