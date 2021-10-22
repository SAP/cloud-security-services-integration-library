/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.k8s;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;

/**
 * The K8sServiceConfigurationProvider provides the information of all bound
 * service configurations.
 */
class K8sServiceConfigurationProvider {
	private static final Logger LOGGER = LoggerFactory.getLogger(K8sServiceConfigurationProvider.class);
	private static final String APPLICATION = "APPLICATION";

	private DefaultServiceManagerService serviceManagerClient;
	private final K8sServiceConfigurationResolver serviceConfigurationResolver;

	K8sServiceConfigurationProvider() {
		this.serviceConfigurationResolver = new K8sServiceConfigurationResolver();
		if (serviceConfigurationResolver
				.loadOauth2ServiceConfig(Service.XSUAA).size() > 1
				&& serviceConfigurationResolver.loadServiceManagerConfig() != null) {
			this.serviceManagerClient = new DefaultServiceManagerService(
					serviceConfigurationResolver.loadServiceManagerConfig());
		}
	}

	void setServiceManagerClient(DefaultServiceManagerService serviceManagerClient) {
		this.serviceManagerClient = serviceManagerClient;
	}

	/**
	 * Gets all service configurations from the mounted file volumes.
	 *
	 * @return the service configurations map of IAS and XSUAA services with their
	 *         corresponding OAuth2ServiceConfigurations. For Xsuaa Map key is the
	 *         service plan name, for IAS key is the service instance name.
	 */
	EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> getServiceConfigurations() {
		EnumMap<Service, Map<String, OAuth2ServiceConfiguration>> serviceConfigurations = new EnumMap<>(Service.class);

		serviceConfigurations.put(Service.XSUAA, mapXsuaaServicePlans(serviceConfigurationResolver
				.loadOauth2ServiceConfig(Service.XSUAA)));
		serviceConfigurations.put(Service.IAS, serviceConfigurationResolver
				.loadOauth2ServiceConfig(Service.IAS));

		return serviceConfigurations;
	}

	private Map<String, OAuth2ServiceConfiguration> mapXsuaaServicePlans(
			Map<String, OAuth2ServiceConfiguration> allXsuaaServices) {
		Map<String, OAuth2ServiceConfiguration> allXsuaaServicesWithPlans = new HashMap<>();// <planName, config>

		if (!allXsuaaServices.isEmpty() && allXsuaaServices.size() > 1) {
			if (serviceManagerClient == null) {
				return getSingleXsuaaConfigWithApplicationPlan(allXsuaaServices, "No service-manager client available");
			}
			Map<String, String> serviceInstancePlans = serviceManagerClient.getServiceInstancePlans();// <xsuaaName,planName>
			if (serviceInstancePlans.isEmpty()) {
				return getSingleXsuaaConfigWithApplicationPlan(allXsuaaServices,
						"No plans or instances were fetched from service manager");
			}
			allXsuaaServices.keySet().forEach(
					k -> allXsuaaServicesWithPlans.put(serviceInstancePlans.get(k).toUpperCase(),
							allXsuaaServices.get(k)));
		} else if (allXsuaaServices.size() == 1) {
			return getSingleXsuaaConfigWithApplicationPlan(allXsuaaServices, null);
		}
		return allXsuaaServicesWithPlans;
	}

	private Map<String, OAuth2ServiceConfiguration> getSingleXsuaaConfigWithApplicationPlan(
			Map<String, OAuth2ServiceConfiguration> allXsuaaServices, @Nullable String warningMessage) {
		Map.Entry<String, OAuth2ServiceConfiguration> xsuaaServiceEntrySet = allXsuaaServices.entrySet().iterator()
				.next();
		if (warningMessage != null) {
			LOGGER.warn("{}, taking first Xsuaa service instance '{}' and assigning 'application' plan", warningMessage,
					xsuaaServiceEntrySet.getKey());
		} else {
			LOGGER.info("Assigning 'application' plan to '{}' service", xsuaaServiceEntrySet.getKey());
		}
		return Collections.singletonMap(APPLICATION, xsuaaServiceEntrySet.getValue());
	}
}
