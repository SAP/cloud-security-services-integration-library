package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.cf.CFConstants.Plan;

public class CFEnvParser {
	private static final Logger logger = LoggerFactory.getLogger(CFEnvParser.class);

	private final DefaultJsonObject jsonObject;

	public CFEnvParser(String vcapJsonString) {
		jsonObject = new DefaultJsonObject(vcapJsonString);
	}

	/**
	 * Loads all configurations of all service instances of the dedicated service.
	 * @param service the name of the service
	 * @return the list of all found configurations or empty list, in case there are not service bindings.
	 * @deprecated as multiple bindings of identity service is not anymore necessary
	 * with the unified broker plan, this method is deprecated. Use {@link #load(CFService)} instead.
	 */
	@Deprecated
	public List<CFOAuth2ServiceConfiguration> loadAll(CFService service) {
		List<JsonObject> instanceObjects = jsonObject.getJsonObjects(service.getName());
		if (instanceObjects.size() > 1) {
			logger.warn("More than one service configuration available. Please make use of unified 'broker' plan.");
		}
		return convertToServiceConfigurations(service, instanceObjects);
	}

	/**
	 * Loads the configuration of of the dedicated service instance.
	 * @param service the name of the service
	 * @return the configuration of the dedicated service instance.
	 * In case of XSUAA service you may still have multiple bindings.
	 * In this case the configuration of the service of application plan is returned.
	 *
	 * Note: with the unified broker plan there is no longer a need to have multiple bindings.
	 */
	@Nullable
	public CFOAuth2ServiceConfiguration load(CFService service) {
		if(CFService.XSUAA.equals(service)) {
			return loadXsuaa();
		}
		logger.warn("Identity Service {} is currently not supported.", service.getName());
		return null;
	}

	private CFOAuth2ServiceConfiguration loadXsuaa() {
		List<CFOAuth2ServiceConfiguration> availableServices = loadAll(CFService.XSUAA);
		Optional<CFOAuth2ServiceConfiguration> applicationService = getServiceByPlan(availableServices,
				Plan.APPLICATION);
		Optional<CFOAuth2ServiceConfiguration> brokerService = getServiceByPlan(availableServices,
				Plan.BROKER);
		if (applicationService.isPresent()) {
			return applicationService.get();
		}
		return brokerService.orElse(null);
	}

	private List<CFOAuth2ServiceConfiguration> convertToServiceConfigurations(CFService service, Collection<JsonObject> instanceObjects) {
		if (instanceObjects == null) {
			return Collections.EMPTY_LIST;
		}
		return instanceObjects.stream().map((JsonObject object) -> convertToServiceConfiguration(service, object)).collect(Collectors.toList());
	}

	private CFOAuth2ServiceConfiguration convertToServiceConfiguration(CFService service, JsonObject jsonObject) {
		return new CFOAuth2ServiceConfiguration(service, jsonObject);
	}

	public Optional<CFOAuth2ServiceConfiguration> getServiceByPlan(
			Collection<CFOAuth2ServiceConfiguration> availableServices, Plan cfServicePlan) {
		return availableServices.stream()
				.filter(service -> cfServicePlan.equals(service.getPlan()))
				.findFirst();
	}

}
