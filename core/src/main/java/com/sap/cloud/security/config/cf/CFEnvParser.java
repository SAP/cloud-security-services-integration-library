package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static com.sap.cloud.security.config.cf.CFConstants.Plan;
import static com.sap.cloud.security.config.cf.CFConstants.ServiceType;

public class CFEnvParser {
	private static final Logger logger = LoggerFactory.getLogger(CFEnvParser.class);

	private final DefaultJsonObject jsonObject;

	public CFEnvParser(String vcapJsonString) {
		jsonObject = new DefaultJsonObject(vcapJsonString);
	}

	@Deprecated
	public List<CFOAuth2ServiceConfiguration> loadAll(ServiceType serviceType) {
		List<JsonObject> instanceObjects = jsonObject.getJsonObjects(serviceType.propertyName());
		if (instanceObjects.size() > 1) {
			logger.warn("More than one service configuration available!");
		}
		return convertToServiceConfigurations(instanceObjects);
	}

	@Nullable
	public CFOAuth2ServiceConfiguration load(ServiceType serviceType) {
		List<CFOAuth2ServiceConfiguration> availableServices = loadAll(serviceType);
		Optional<CFOAuth2ServiceConfiguration> applicationService = getServiceOfType(availableServices,
				Plan.APPLICATION);
		Optional<CFOAuth2ServiceConfiguration> brokerService = getServiceOfType(availableServices,
				Plan.BROKER);
		if (applicationService.isPresent()) {
			return applicationService.get();
		}
		return brokerService.orElse(null);
	}

	private List<CFOAuth2ServiceConfiguration> convertToServiceConfigurations(Collection<JsonObject> instanceObjects) {
		if (instanceObjects == null) {
			return new ArrayList<>();
		}
		return instanceObjects.stream().map(this::convertToServiceConfiguration).collect(Collectors.toList());
	}

	private Optional<CFOAuth2ServiceConfiguration> getServiceOfType(
			Collection<CFOAuth2ServiceConfiguration> availableServices, Plan planType) {
		return availableServices.stream()
				.filter(service -> planType.equals(service.getPlan()))
				.findFirst();
	}

	private CFOAuth2ServiceConfiguration convertToServiceConfiguration(JsonObject jsonObject) {
		return new CFOAuth2ServiceConfiguration(jsonObject);
	}

}
