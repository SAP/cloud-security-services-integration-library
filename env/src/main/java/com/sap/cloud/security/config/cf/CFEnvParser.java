/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.cf.CFConstants.CREDENTIALS;
import static com.sap.cloud.security.config.cf.CFConstants.IAS.DOMAINS;
import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;

class CFEnvParser {
	private static final Logger logger = LoggerFactory.getLogger(CFEnvParser.class);

	private CFEnvParser() {
	}

	static OAuth2ServiceConfiguration loadForService(Service service, JsonObject serviceJsonObject) {
		return loadForService(service, serviceJsonObject, false);
	}

	/**
	 * Loads all configurations of all identity service instances.
	 *
	 * @return the list of all found configurations or empty list, in case there are
	 *         not service bindings.
	 */
	static Map<Service, List<OAuth2ServiceConfiguration>> loadAll(String vcapServicesJson, String vcapApplicationJson) {
		Map<Service, List<OAuth2ServiceConfiguration>> serviceConfigurations = new HashMap<>(); // NOSONAR
		List<OAuth2ServiceConfiguration> allServices;

		for (Service service : Service.values()) {
			allServices = loadAllForService(service,
					new DefaultJsonObject(vcapServicesJson),
					runInLegacyMode(vcapApplicationJson));
			serviceConfigurations.put(service, allServices);
		}
		return serviceConfigurations;
	}

	static List<OAuth2ServiceConfiguration> loadAllForService(Service service, JsonObject vcapServicesJson,
			boolean isLegacyMode) {
		List<JsonObject> serviceJsonObjects = vcapServicesJson.getJsonObjects(service.getCFName());
		if (service == XSUAA && serviceJsonObjects.size() > 1) {
			logger.info(
					"More than one service configuration available for service {}.",
					service);
		}
		return serviceJsonObjects.stream()
				.map((JsonObject serviceJsonObject) -> loadForService(service, serviceJsonObject, isLegacyMode))
				.collect(Collectors.toList());
	}

	static OAuth2ServiceConfiguration loadForService(Service service, JsonObject serviceJsonObject,
			boolean isLegacyMode) {
		Map<String, String> serviceBindingProperties = serviceJsonObject.getKeyValueMap();
		try {
			Map<String, String> serviceBindingCredentials = serviceJsonObject.getJsonObject(CREDENTIALS)
					.getKeyValueMap();
			OAuth2ServiceConfigurationBuilder builder = OAuth2ServiceConfigurationBuilder.forService(service)
					.withProperties(serviceBindingCredentials)
					.withProperty(SERVICE_PLAN,
							CFConstants.Plan.from(serviceBindingProperties.get(SERVICE_PLAN)).toString())
					.runInLegacyMode(isLegacyMode);
			if (Service.IAS == service) {
				builder.withDomains(serviceJsonObject.getJsonObject(CREDENTIALS).getAsStringList(DOMAINS)
						.toArray(new String[0]));
			}
			return builder.build();
		} catch (JsonParsingException e) {
			String errDescription = "The credentials of 'VCAP_SERVICES' can not be parsed for service '"
					+ service + "' ('" + e.getMessage() + "'). Please check the service binding.";
			logger.error(errDescription);
			throw new JsonParsingException(errDescription);
		}
	}

	private static boolean runInLegacyMode(String vcapApplicationJson) {
		return new DefaultJsonObject(vcapApplicationJson).contains("xs_api");
	}
}
