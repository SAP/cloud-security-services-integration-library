/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.environment.servicebinding.api.DefaultServiceBindingAccessor;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.security.config.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;
import static com.sap.cloud.security.config.k8s.K8sConstants.Plan;

/**
 * Loads the OAuth configuration ({@link OAuth2ServiceConfiguration}) of a
 * supported identity {@link Service} in the Kubernetes Environment by accessing
 * defaults service secrets paths "/etc/secrets/sapbtp/xsuaa" for Xsuaa service
 * or "/etc/secrets/sapbtp/identity" for IAS service.
 */
public class K8sEnvironment implements Environment {
	private static final Logger LOGGER = LoggerFactory.getLogger(K8sEnvironment.class);

	static K8sEnvironment instance;
	private final Map<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfigurations;

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

		Map<String, OAuth2ServiceConfiguration> xsuaaPlans = serviceBindings.stream()
				.filter(b -> Service.XSUAA.equals(Service.from(b.getServiceName().orElse(null))))
				.map(ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder)
				.filter(Objects::nonNull)
				.map(OAuth2ServiceConfigurationBuilder::build)
				.collect(Collectors.toMap(config -> config.getProperty(SERVICE_PLAN),
						Function.identity()));
		Map<String, OAuth2ServiceConfiguration> identityPlans = serviceBindings.stream()
				.filter(b -> Service.IAS.equals(Service.from(b.getServiceName().orElse(null))))
				.map(ServiceBindingMapper::mapToOAuth2ServiceConfigurationBuilder)
				.filter(Objects::nonNull)
				.map(OAuth2ServiceConfigurationBuilder::build)
				.collect(Collectors.toMap(config -> config.getProperty(SERVICE_PLAN),
						Function.identity()));
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
	Map<String, OAuth2ServiceConfiguration> getServiceConfigurationsOf(Service service) {
		return serviceConfigurations.getOrDefault(service, Collections.emptyMap());
	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfiguration() {
		return Optional.ofNullable(getServiceConfigurationsOf(Service.XSUAA).get(Plan.APPLICATION.name()))
				.orElse(Optional.ofNullable(getServiceConfigurationsOf(Service.XSUAA).get(Plan.BROKER.name()))
						.orElse(Optional.ofNullable(getServiceConfigurationsOf(Service.XSUAA).get(Plan.SPACE.name()))
								.orElse(Optional
										.ofNullable(getServiceConfigurationsOf(Service.XSUAA).get(Plan.DEFAULT.name()))
										.orElse(null))));

	}

	@Nullable
	@Override
	public OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange() {
		if (getNumberOfXsuaaConfigurations() > 1) {
			return getServiceConfigurationsOf(Service.XSUAA).get(Plan.BROKER.name());
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

}
