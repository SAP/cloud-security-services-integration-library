package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.*;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.cf.CFConstants.Plan;

public class CFEnvParser {
	private static final Logger logger = LoggerFactory.getLogger(CFEnvParser.class);

	private final Map<CFService, List<CFOAuth2ServiceConfiguration>> serviceConfigurations;

	public CFEnvParser(String vcapJsonString) {
		serviceConfigurations = new HashMap<>();
		List<CFOAuth2ServiceConfiguration> allServices = extractAllServices(CFService.XSUAA,
				new DefaultJsonObject(vcapJsonString));
		serviceConfigurations.put(CFService.XSUAA, allServices);
	}

	/**
	 * Loads all configurations of all service instances of the dedicated service.
	 *
	 * @param service
	 *            the name of the service
	 * @return the list of all found configurations or empty list, in case there are
	 *         not service bindings.
	 * @deprecated as multiple bindings of identity service is not anymore necessary
	 *             with the unified broker plan, this method is deprecated. Use
	 *             {@link #load(CFService)} instead.
	 */
	@Deprecated
	public List<CFOAuth2ServiceConfiguration> loadAll(CFService service) {
		return serviceConfigurations.getOrDefault(service, new ArrayList<>());
	}

	/**
	 * Loads the configuration of of the dedicated service instance.
	 *
	 * @param service
	 *            the name of the service
	 * @return the configuration of the dedicated service instance. In case of XSUAA
	 *         service you may still have multiple bindings. In this case the
	 *         configuration of the service of application plan is returned.
	 *         <p>
	 *         Note: with the unified broker plan there is no longer a need to have
	 *         multiple bindings.
	 */
	@Nullable
	public CFOAuth2ServiceConfiguration load(CFService service) {
		if (CFService.XSUAA == service) {
			return loadXsuaa();
		}
		logger.warn("Identity Service {} is currently not supported.", service.getName());
		return null;
	}

	@Nullable
	public CFOAuth2ServiceConfiguration loadByPlan(CFService service, Plan plan) {
		return loadAll(service).stream()
				.filter(configuration -> configuration.getPlan() == plan)
				.findFirst()
				.orElse(null);
	}

	private CFOAuth2ServiceConfiguration loadXsuaa() {
		Optional<CFOAuth2ServiceConfiguration> applicationService = Optional
				.ofNullable(loadByPlan(CFService.XSUAA, Plan.APPLICATION));
		Optional<CFOAuth2ServiceConfiguration> brokerService = Optional
				.ofNullable(loadByPlan(CFService.XSUAA, Plan.BROKER));
		if (applicationService.isPresent()) {
			return applicationService.get();
		}
		return brokerService.orElse(null);
	}

	private List<CFOAuth2ServiceConfiguration> extractAllServices(CFService service, DefaultJsonObject jsonObject) {
		List<JsonObject> jsonServiceObjects = jsonObject.getJsonObjects(service.getName());
		if (jsonServiceObjects.size() > 1) {
			logger.warn("More than one service configuration available. Please make use of unified 'broker' plan.");
		}
		return jsonServiceObjects.stream()
				.map((JsonObject object) -> new CFOAuth2ServiceConfiguration(service, object))
				.collect(Collectors.toList());
	}

}
