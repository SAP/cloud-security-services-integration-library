/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.security.json.DefaultJsonObject;

import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.ServiceConstants.SERVICE_PLAN;
import static com.sap.cloud.security.config.ServiceConstants.VCAP_APPLICATION;

/**
 * Accessor for service configurations that are defined in the environment. Uses
 * a {@link com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor}
 * to read service bindings from the environment and supplies accessor methods
 * for service-specific configuration objects parsed from these bindings. *
 */
public class ServiceBindingEnvironment implements Environment {
	private final ServiceBindingAccessor serviceBindingAccessor;
	private UnaryOperator<String> environmentVariableReader = System::getenv;
	private Map<Service, List<OAuth2ServiceConfiguration>> serviceConfigurations;

	/**
	 * Uses the
	 * {@link com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor}
	 * singleton to read service bindings from the environment.
	 */
	public ServiceBindingEnvironment() {
		this(DefaultServiceBindingAccessor.getInstance());
	}

	/**
	 * Uses the given ServiceBindingAccessor to read service bindings from the
	 * environment. For instance, a
	 * {@link com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor}
	 * can be used to get service configurations for testing based on a local JSON.
	 */
	public ServiceBindingEnvironment(ServiceBindingAccessor serviceBindingAccessor) {
		this.serviceBindingAccessor = serviceBindingAccessor;
	}

	/**
	 * Overwrites {@link System#getenv} with a custom environment variable reader.
	 * The given reader is only used to determine if an XS legacy environment is
	 * present. Instead, the reading of service bindings is based on the
	 * ServiceBindingAccessor supplied during construction.
	 */
	public ServiceBindingEnvironment withEnvironmentVariableReader(UnaryOperator<String> environmentVariableReader) {
		this.environmentVariableReader = environmentVariableReader;
		this.clearServiceConfigurations(); // re-compute service configurations on next access
		return this;
	}

	/**
	 * Gets the configuration of the primary XSUAA service binding. The primary
	 * binding is determined based on the service plan. The priority of the service
	 * plans used for this, is (from high to low priority):
	 * <ul>
	 * <li>APPLICATION</li>
	 * <li>BROKER</li>
	 * <li>SPACE</li>
	 * <li>DEFAULT</li>
	 * </ul>
	 */
	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfiguration() {
		List<ServiceConstants.Plan> orderedServicePlans = List.of(ServiceConstants.Plan.APPLICATION, ServiceConstants.Plan.BROKER,
				ServiceConstants.Plan.SPACE, ServiceConstants.Plan.DEFAULT);
		List<OAuth2ServiceConfiguration> xsuaaConfigurations = getServiceConfigurationsAsList().get(XSUAA);

		return xsuaaConfigurations.stream()
				.filter(config -> getServicePlan(config) != null)
				.filter(config -> orderedServicePlans.contains(getServicePlan(config)))
				.min(Comparator.comparingInt(config -> orderedServicePlans.indexOf(getServicePlan(config))))
				.orElse(null);
	}

	@Override
	public int getNumberOfXsuaaConfigurations() {
		return getServiceConfigurationsAsList().get(XSUAA).size();
	}

	/**
	 * Gets the configuration of the XSUAA service binding that is used for token
	 * exchange. Returns the configuration of the service binding with service plan
	 * BROKER if present, otherwise delegates to
	 * {@link ServiceBindingEnvironment#getXsuaaConfiguration()}.
	 */
	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
		if (getNumberOfXsuaaConfigurations() > 1) {
			return getServiceConfigurations().get(XSUAA).get(ServiceConstants.Plan.BROKER);
		}

		return getXsuaaConfiguration();
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getIasConfiguration() {
		return getServiceConfigurations().get(IAS).values().stream().findFirst().orElse(null);
	}

	/**
	 * Gives access to all service configurations parsed from the environment. The
	 * service configurations are parsed on the first access, then cached.
	 *
	 * @return the service configurations grouped by service
	 */
	public Map<Service, List<OAuth2ServiceConfiguration>> getServiceConfigurationsAsList() {
		if (serviceConfigurations == null) {
			this.readServiceConfigurations();
		}

		return this.serviceConfigurations;
	}

	/**
	 * Gives access to all service configurations parsed from the environment. The
	 * service configurations are parsed on the first access, then cached.
	 *
	 * Note that the result contains only one service configuration per service plan and does not contain configurations
	 * with a service plan other than those from {@link ServiceConstants}#Plan.
	 * Use {@link ServiceBindingEnvironment#getServiceConfigurationsAsList()} to get a complete list of configurations.
	 *
	 * @return the service configurations grouped first by service, then by service plan.
	 */
	@Override
	public Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> getServiceConfigurations() {
		if (serviceConfigurations == null) {
			this.readServiceConfigurations();
		}

		Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> result = new HashMap<>();

		for (Map.Entry<Service, List<OAuth2ServiceConfiguration>> entry : serviceConfigurations.entrySet()) {
			Service service = entry.getKey();
			List<OAuth2ServiceConfiguration> configurations = entry.getValue();

			Map<ServiceConstants.Plan, OAuth2ServiceConfiguration> planConfigurations = configurations.stream()
					.filter(config -> getServicePlan(config) != null)
					.collect(Collectors.toMap(
							config -> ServiceConstants.Plan.from(config.getProperty(SERVICE_PLAN)),
							Function.identity(),
							(a, b) -> a
					));

			result.put(service, planConfigurations);
		}

		return result;
	}

	/** Parses the service configurations from the environment. */
	private void readServiceConfigurations() {
		List<ServiceBinding> serviceBindings = serviceBindingAccessor.getServiceBindings();

		serviceConfigurations = Stream.of(Service.values())
				.collect(Collectors.toMap(Function.identity(), service -> serviceBindings.stream()
						.filter(b -> service.equals(Service.from(b.getServiceName().orElse(""))))
						.map(ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder)
						.filter(Objects::nonNull)
						.map(builder -> builder.runInLegacyMode(runInLegacyMode()))
						.map(OAuth2ServiceConfigurationBuilder::build)
						.toList()));
	}

	/**
	 * Clears service configurations, so they are computed again on next access.
	 * Must be called again if the environment has changed, to update the service
	 * configurations that are returned on the next access.
	 */
	private void clearServiceConfigurations() {
		this.serviceConfigurations = null;
	}

	@Nullable
	private ServiceConstants.Plan getServicePlan(OAuth2ServiceConfiguration config) {
		try {
			return ServiceConstants.Plan.from(config.getProperty(SERVICE_PLAN));
		} catch(IllegalArgumentException e) {
			return null;
		}
	}

	private boolean runInLegacyMode() {
		String vcapApplicationJson = environmentVariableReader.apply(VCAP_APPLICATION);

		if (vcapApplicationJson != null) {
			return new DefaultJsonObject(vcapApplicationJson).contains("xs_api");
		}

		return false;
	}
}
