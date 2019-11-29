package com.sap.cloud.security.config.cf;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.cf.CFConstants.VCAP_SERVICES;

import javax.annotation.Nullable;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants.Plan;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

public class CFEnvironment implements Environment {

	private Map<Service, List<CFOAuth2ServiceConfiguration>> serviceConfigurations;
	private Function<String, String> systemEnvironmentProvider;
	private Function<String, String> systemPropertiesProvider;

	private CFEnvironment() {
		// implemented in getInstance() factory method
	}

	public static CFEnvironment getInstance() {
		return getInstance(System::getenv, System::getProperty);
	}

	static CFEnvironment getInstance(Function<String, String> systemEnvironmentProvider,
			Function<String, String> systemPropertiesProvider) {
		CFEnvironment instance = new CFEnvironment();
		instance.systemEnvironmentProvider = systemEnvironmentProvider;
		instance.systemPropertiesProvider = systemPropertiesProvider;
		instance.serviceConfigurations = CFEnvParser.loadAll(instance.extractVcapJsonString());
		return instance;
	}

	@Override
	public OAuth2ServiceConfiguration getXsuaaServiceConfiguration() {
		return loadXsuaa();
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getIasServiceConfiguration() {
		// return
		// loadAll(IAS).stream().filter(Objects::nonNull).findFirst().orElse(null);
		throw new UnsupportedOperationException("Bindings of IAS Identity Service is not yet supported.");
	}

	@Override
	public int getNumberOfXsuaaServices() {
		return loadAll(XSUAA).size();
	}

	@Override
	public OAuth2ServiceConfiguration getXsuaaServiceConfigurationForTokenExchange() {
		if (getNumberOfXsuaaServices() > 1) {
			return loadByPlan(XSUAA, Plan.BROKER);
		}
		return getXsuaaServiceConfiguration();
	}

	/**
	 * Loads all configurations of all service instances of the dedicated service.
	 *
	 * @param service
	 *            the name of the service
	 * @return the list of all found configurations or empty list, in case there are
	 *         not service bindings.
	 * @deprecated as multiple bindings of XSUAA identity service is not anymore
	 *             necessary with the unified broker plan, this method is
	 *             deprecated.
	 */
	@Deprecated
	List<CFOAuth2ServiceConfiguration> loadAll(Service service) {
		return serviceConfigurations.getOrDefault(service, new ArrayList<>());
	}

	@Override
	public Type getType() {
		return Type.CF;
	}

	private String extractVcapJsonString() {
		String env = systemPropertiesProvider.apply(VCAP_SERVICES);
		if (env == null) {
			env = systemEnvironmentProvider.apply(VCAP_SERVICES);
		}
		return env != null ? env : "{}";
	}

	private CFOAuth2ServiceConfiguration loadXsuaa() {
		Optional<CFOAuth2ServiceConfiguration> applicationService = Optional
				.ofNullable(loadByPlan(XSUAA, Plan.APPLICATION));
		Optional<CFOAuth2ServiceConfiguration> brokerService = Optional
				.ofNullable(loadByPlan(XSUAA, Plan.BROKER));
		if (applicationService.isPresent()) {
			return applicationService.get();
		}
		return brokerService.orElse(null);
	}

	@Nullable
	public CFOAuth2ServiceConfiguration loadByPlan(Service service, Plan plan) {
		return loadAll(service).stream()
				.filter(configuration -> configuration.getPlan() == plan)
				.findFirst()
				.orElse(null);
	}

}
