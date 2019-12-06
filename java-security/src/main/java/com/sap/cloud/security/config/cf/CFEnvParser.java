package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.Service.XSUAA;

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
	static Map<Service, List<CFOAuth2ServiceConfiguration>> loadAll(String vcapJsonString) {
		Map<Service, List<CFOAuth2ServiceConfiguration>> serviceConfigurations = new HashMap<>(); // NOSONAR
		List<CFOAuth2ServiceConfiguration> allServices;
		for (Service s : Service.values()) {
			allServices = extractAllServices(s,
					new DefaultJsonObject(vcapJsonString));
			serviceConfigurations.put(s, allServices);
		}
		return serviceConfigurations;
	}

	static List<CFOAuth2ServiceConfiguration> extractAllServices(Service service, JsonObject vcapJsonObject) {
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

	public static CFOAuth2ServiceConfiguration extract(Service service, JsonObject serviceJsonObject) {
		Map<String, String> xsuaaConfigMap = serviceJsonObject.getKeyValueMap();
		Map<String, String> credentialsMap = serviceJsonObject.getJsonObject(CFConstants.CREDENTIALS).getKeyValueMap();

		return new CFOAuth2ServiceConfiguration(service, xsuaaConfigMap, credentialsMap);
	}
}
