package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.XSUAA;
import static com.sap.cloud.security.config.cf.CFConstants.SERVICE_PLAN;

class CFEnvParser {
	private static final Logger logger = LoggerFactory.getLogger(CFEnvParser.class);

	private CFEnvParser() {
	}

	/**
	 * Loads all configurations of all identity service instances.
	 *
	 * @return the list of all found configurations or empty list, in case there are
	 *         not service bindings.
	 */
	static Map<Service, List<OAuth2ServiceConfiguration>> loadAll(String vcapJsonString) {
		Map<Service, List<OAuth2ServiceConfiguration>> serviceConfigurations = new HashMap<>(); // NOSONAR
		List<OAuth2ServiceConfiguration> allServices;
		for (Service s : Service.values()) {
			allServices = extractAllServices(s,
					new DefaultJsonObject(vcapJsonString));
			serviceConfigurations.put(s, allServices);
		}
		return serviceConfigurations;
	}

	static List<OAuth2ServiceConfiguration> extractAllServices(Service service, JsonObject vcapJsonObject) {
		List<JsonObject> serviceJsonObjects = vcapJsonObject.getJsonObjects(service.getCFName());
		if (service == XSUAA && serviceJsonObjects.size() > 1) {
			logger.warn(
					"More than one service configuration available for service {}. Please make use of unified 'broker' plan.",
					service);
		}
		return serviceJsonObjects.stream()
				.map((JsonObject serviceJsonObject) -> extract(service, serviceJsonObject))
				.collect(Collectors.toList());
	}

	public static OAuth2ServiceConfiguration extract(Service service, JsonObject serviceJsonObject) {
		Map<String, String> serviceBindingProperties = serviceJsonObject.getKeyValueMap();
		Map<String, String> serviceBindingCredentials = serviceJsonObject.getJsonObject(CFConstants.CREDENTIALS)
				.getKeyValueMap();

		return OAuth2ServiceConfigurationBuilder.forService(service)
				.withProperties(serviceBindingCredentials)
				.withProperty(SERVICE_PLAN, serviceBindingProperties.get(SERVICE_PLAN))
				.build();
	}

}
