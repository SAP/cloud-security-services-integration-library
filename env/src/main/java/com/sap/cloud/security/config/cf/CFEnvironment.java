/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p> <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.cf;

import com.sap.cloud.environment.servicebinding.SapVcapServicesServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.environment.servicebinding.api.ServiceBindingAccessor;
import com.sap.cloud.security.annotation.Beta;
import com.sap.cloud.security.config.*;
import com.sap.cloud.security.config.cf.CFConstants.Plan;
import com.sap.cloud.security.json.DefaultJsonObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.IAS;
import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.cf.CFConstants.VCAP_APPLICATION;
import static com.sap.cloud.security.config.cf.CFConstants.VCAP_SERVICES;

/**
 * Loads the OAuth configuration ({@link OAuth2ServiceConfiguration}) of a
 * supported identity {@link Service} in the SAP CP Cloud Foundry Environment by
 * parsing the {@code VCAP_SERVICES} system environment variable.
 */
public class CFEnvironment implements Environment {

	private ServiceBindingAccessor serviceBindingAccessor;
	private UnaryOperator<String> environmentVariableReader = System::getenv;
	private final Map<Service, List<OAuth2ServiceConfiguration>> serviceConfigurations;

	private CFEnvironment() {
		serviceConfigurations = new EnumMap<>(Service.class);
	}

	/**
	 * Creates a new CFEnvironment that reads {@link CFConstants#VCAP_SERVICES} from
	 * 		<ul>
	 * 		    <li>system properties OR</li>
	 * 		    <li>environment variables if system properties has no {@link CFConstants#VCAP_SERVICES}.</li>
	 * 		</ul>
	 * */
	public static CFEnvironment getInstance() {
		return getInstance(pickEnvironmentAccessor(System::getProperty, System::getenv));
	}

	/**
	 * Creates a new CFEnvironment that reads {@link CFConstants#VCAP_SERVICES} via the provided vcapProvider.
	 * <br>
	 * <b>Example use:</b>
	 * CFEnvironment.getInstance(any -&gt; VCAP_SERVICES_JSON)
	 *
	 * @param vcapProvider provides Cloud Foundry environment configurations as JSON string including but not
	 *                        necessarily limited to key {@link com.sap.cloud.security.config.cf.CFConstants#VCAP_SERVICES}.
	 * */
	public static CFEnvironment getInstance(UnaryOperator<String> vcapProvider) {
		CFEnvironment instance = new CFEnvironment();
		instance.environmentVariableReader = vcapProvider;
		instance.serviceBindingAccessor = new SapVcapServicesServiceBindingAccessor(vcapProvider);
		instance.readServiceConfigurations();
		return instance;
	}

	/**
	 * Beta feature.
	 *
	 * Creates a new CFEnvironment that uses the provided ServiceBindingAccessor to create a configuration.
	 * @param serviceBindingAccessor a ServiceBindingAccessor that is used to build a {@link OAuth2ServiceConfiguration}
	 * from the service bindings.
	 */
	@Beta
	public static CFEnvironment getInstance(ServiceBindingAccessor serviceBindingAccessor) {
		CFEnvironment instance = new CFEnvironment();
		instance.serviceBindingAccessor = serviceBindingAccessor;
		instance.readServiceConfigurations();

		return instance;
	}

	/**
	 * @deprecated in favor of *
	 *             {@link com.sap.cloud.security.config.cf.CFEnvironment#getInstance(UnaryOperator)}.
	 *             * Will be deleted with version 3.0.0.
	 */
	@Deprecated
	public static CFEnvironment getInstance(UnaryOperator<String> systemEnvironmentProvider,
			UnaryOperator<String> systemPropertiesProvider) {
		return getInstance(pickEnvironmentAccessor(systemEnvironmentProvider, systemPropertiesProvider));
	}

	private static UnaryOperator<String> pickEnvironmentAccessor(UnaryOperator<String> systemEnvironmentProvider,
			UnaryOperator<String> systemPropertiesProvider) {
		String env = systemPropertiesProvider.apply(VCAP_SERVICES);
		if (env != null) {
			return systemPropertiesProvider;
		} else {
			env = systemEnvironmentProvider.apply(VCAP_SERVICES);
			if (env != null) {
				return systemEnvironmentProvider;
			}
		}
		return systemEnvironmentProvider;
	}

	private void readServiceConfigurations() {
		List<ServiceBinding> serviceBindings = serviceBindingAccessor.getServiceBindings();

		List<OAuth2ServiceConfiguration> xsuaaPlans = serviceBindings.stream()
				.filter(b -> Service.XSUAA.equals(Service.from(b.getServiceName().orElse(""))))
				.map(ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder)
				.filter(Objects::nonNull)
				.map(builder -> builder.runInLegacyMode(runInLegacyMode()))
				.map(OAuth2ServiceConfigurationBuilder::build)
				.collect(Collectors.toList());
		List<OAuth2ServiceConfiguration> iasPlans = serviceBindings.stream()
				.filter(b -> Service.IAS.equals(Service.from(b.getServiceName().orElse(""))))
				.map(ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder)
				.filter(Objects::nonNull)
				.map(OAuth2ServiceConfigurationBuilder::build)
				.collect(Collectors.toList());

		serviceConfigurations.put(XSUAA, xsuaaPlans);
		serviceConfigurations.put(IAS, iasPlans);
	}

	@Override
	@Nonnull
	public Type getType() {
		return Type.CF;
	}

	@Override
	public OAuth2ServiceConfiguration getXsuaaConfiguration() {
		Optional<OAuth2ServiceConfiguration> applicationService = Optional
				.ofNullable(loadForServicePlan(XSUAA, Plan.APPLICATION));
		Optional<OAuth2ServiceConfiguration> brokerService = Optional
				.ofNullable(loadForServicePlan(XSUAA, Plan.BROKER));
		Optional<OAuth2ServiceConfiguration> legacyService = Optional
				.ofNullable(loadForServicePlan(XSUAA, Plan.SPACE));
		Optional<OAuth2ServiceConfiguration> legacyServiceSimple = Optional
				.ofNullable(loadForServicePlan(XSUAA, Plan.DEFAULT));

		return applicationService.orElse(
				brokerService.orElse(
						legacyService.orElse(
								legacyServiceSimple.orElse(null))));
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getIasConfiguration() {
		return loadAllForService(IAS).stream().filter(Objects::nonNull).findFirst().orElse(null);
	}

	@Override
	public int getNumberOfXsuaaConfigurations() {
		return loadAllForService(XSUAA).size();
	}

	@Override
	public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
		if (getNumberOfXsuaaConfigurations() > 1) {
			return loadForServicePlan(XSUAA, Plan.BROKER);
		}
		return getXsuaaConfiguration();
	}

	/**
	 * Loads the configuration for a dedicated service plan.
	 *
	 * @param service
	 *            the name of the service
	 * @param plan
	 *            the name of the service plan
	 * @return the configuration or null, if there is not such binding information
	 *         for the given service plan.
	 */
	@Nullable
	public OAuth2ServiceConfiguration loadForServicePlan(Service service, Plan plan) {
		return loadAllForService(service).stream()
				.filter(configuration -> Plan.from(configuration.getProperty(CFConstants.SERVICE_PLAN)).equals(plan))
				.sorted(new Comparator<OAuth2ServiceConfiguration>() {

					@Override
					public int compare(OAuth2ServiceConfiguration o1, OAuth2ServiceConfiguration o2) {
						if (o1 == null && o2 == null) {
							return 0;
						}
						if (o1 == null) {
							return 1;
						}
						if (o2 == null) {
							return -1;
						}
						
						/*
						 * Note that we know here that we are in a CF Environment!
						 * The CF Environment variables always contain a "name" property.
						 * The call ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder
						 * ensured that the property was transfered.
						 */
						
						final String o1Name = o1.getProperty(CFConstants.NAME);
						final String o2Name = o2.getProperty(CFConstants.NAME);
						
						if (o1Name == null && o2Name == null) {
							return 0;
						}
						if (o1Name == null) {
							return 1;
						}
						if (o2Name == null) {
							return -1;
						}
						
						return o1Name.compareTo(o2Name);
					}
				})
				.findFirst()
				.orElse(null);
	}

	/**
	 * Loads all configurations of all service instances of the dedicated service.
	 *
	 * @param service
	 *            the service name
	 * @return the list of all found configurations or empty list, in case there are
	 *         no service bindings.
	 */
	List<OAuth2ServiceConfiguration> loadAllForService(Service service) {
		return serviceConfigurations.getOrDefault(service, Collections.emptyList());
	}

	private boolean runInLegacyMode() {
		String vcapApplicationJson = environmentVariableReader.apply(VCAP_APPLICATION);
		if (vcapApplicationJson != null) {
			return new DefaultJsonObject(vcapApplicationJson).contains("xs_api");
		}
		return false;
	}
}
