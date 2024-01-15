/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.security.config.*;
import com.sap.cloud.security.config.k8s.K8sConstants.Plan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;

/**
 * Loads the OAuth configuration ({@link OAuth2ServiceConfiguration}) of a
 * supported identity {@link Service} in the Kubernetes Environment by accessing
 * defaults service secrets paths "/etc/secrets/sapbtp/xsuaa" for Xsuaa service
 * or "/etc/secrets/sapbtp/identity" for IAS service.
 */
public class K8sEnvironment implements Environment {
	private static final Logger LOGGER = LoggerFactory.getLogger(K8sEnvironment.class);

	static K8sEnvironment instance;
	private final Map<Service, EnumMap<K8sConstants.Plan, OAuth2ServiceConfiguration>> serviceConfigurations;

	private K8sEnvironment() {
		serviceConfigurations = new EnumMap<>(Service.class);
		loadAll();
	}

	public static K8sEnvironment getInstance() {
		if (instance == null) {
			instance = new K8sEnvironment();
		}
		return instance;
	}

	@Nonnull
	@Override
	public Type getType() {
		return Type.KUBERNETES;
	}

	private void loadAll() {
		List<ServiceBinding> serviceBindings = DefaultServiceBindingAccessor.getInstance().getServiceBindings();

		EnumMap<Plan, OAuth2ServiceConfiguration> xsuaaPlans = serviceBindings.stream()
				.filter(b -> Service.XSUAA.equals(Service.from(b.getServiceName().orElse(null))))
				.map(ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder)
				.filter(Objects::nonNull)
				.map(OAuth2ServiceConfigurationBuilder::build)
				.collect(Collectors.toMap(config -> Plan.from(config.getProperty(SERVICE_PLAN)),
						config -> config,
						(l,r) -> {throw new IllegalArgumentException("2 service configurations of the same plan are not supported");},
						() -> new EnumMap<>(Plan.class)));
		EnumMap<Plan, OAuth2ServiceConfiguration> identityPlans = serviceBindings.stream()
				.filter(b -> Service.IAS.equals(Service.from(b.getServiceName().orElse(null))))
				.map(ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder)
				.filter(Objects::nonNull)
				.map(OAuth2ServiceConfigurationBuilder::build)
				.collect(Collectors.toMap(config -> Plan.from(config.getProperty(SERVICE_PLAN)),
						config -> config,
						(l,r) -> {throw new IllegalArgumentException("2 service configurations of the same plan are not supported");},
						() -> new EnumMap<>(Plan.class)));
		serviceConfigurations.put(Service.XSUAA, xsuaaPlans);
		serviceConfigurations.put(Service.IAS, identityPlans);
	}

	/**
	 * Loads all configurations of all service instances of the dedicated service.
	 *
	 * @param service
	 *            the service name
	 * @return the map of all found configurations or empty map, in case there are
	 *         no service bindings.
	 */
	EnumMap<Plan, OAuth2ServiceConfiguration> getServiceConfigurationsOf(Service service) {
		return serviceConfigurations.getOrDefault(service, new EnumMap<>(Plan.class));
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfiguration() {
		return Optional.ofNullable(getServiceConfigurationsOf(Service.XSUAA).get(Plan.APPLICATION))
				.orElse(Optional.ofNullable(getServiceConfigurationsOf(Service.XSUAA).get(Plan.BROKER))
						.orElse(Optional.ofNullable(getServiceConfigurationsOf(Service.XSUAA).get(Plan.SPACE))
								.orElse(getServiceConfigurationsOf(Service.XSUAA).get(Plan.DEFAULT))));

	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
		if (getNumberOfXsuaaConfigurations() > 1) {
			return getServiceConfigurationsOf(Service.XSUAA).get(Plan.BROKER);
		}
		return getXsuaaConfiguration();
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getIasConfiguration() {
		if (getServiceConfigurationsOf(Service.IAS).size() > 1) {
			LOGGER.warn("{} IAS bindings found. Using the first one from the list",
					getServiceConfigurationsOf(Service.IAS).size());
		}
		return getServiceConfigurationsOf(Service.IAS).entrySet().stream().findFirst().map(Map.Entry::getValue)
				.orElse(null);
	}

	@Override
	public int getNumberOfXsuaaConfigurations() {
		return getServiceConfigurationsOf(Service.XSUAA).size();
	}

	@Override
	public Map<Service, List<OAuth2ServiceConfiguration>> getServiceConfigurationsAsList() {
		return this.serviceConfigurations.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, entry -> new ArrayList<>(entry.getValue().values())));
	}

}
