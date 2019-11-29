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
		Map<Service, List<CFOAuth2ServiceConfiguration>> serviceConfigurations = new HashMap<>();
		List<CFOAuth2ServiceConfiguration> allServices;
		for (Service s : Service.values()) {
			allServices = extractAllServices(s,
					new DefaultJsonObject(vcapJsonString));
			serviceConfigurations.put(s, allServices);
		}
		return serviceConfigurations;
	}

	static List<CFOAuth2ServiceConfiguration> extractAllServices(Service service, DefaultJsonObject jsonObject) {
		List<JsonObject> jsonServiceObjects = jsonObject.getJsonObjects(service.getCFName());
		if (service == XSUAA && jsonServiceObjects.size() > 1) {
			logger.warn(
					"More than one service configuration available for service {}. Please make use of unified 'broker' plan.",
					service);
		}
		return jsonServiceObjects.stream()
				.map((JsonObject object) -> new CFOAuth2ServiceConfiguration(service, object))
				.collect(Collectors.toList());
	}

}
