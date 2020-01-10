package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.OAuth2ServiceConfigurationBuilder;
import com.sap.cloud.security.config.Service;

import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.xsuaa.Assertions.*;

public class CFOAuth2ServiceConfiguration implements OAuth2ServiceConfiguration {

	private final Map<String, String> serviceBindingProperties;
	private final OAuth2ServiceConfiguration oAuth2ServiceConfiguration;
	private Plan plan; // lazy read

	CFOAuth2ServiceConfiguration(Service service, Map<String, String> serviceBindingProperties, Map<String, String> serviceBindingCredentials) {
		assertNotNull(serviceBindingProperties, "serviceBindingProperties must not be null");
		assertNotNull(serviceBindingCredentials, "serviceBindingCredentials must not be null");

		this.serviceBindingProperties = serviceBindingProperties;
		oAuth2ServiceConfiguration = createOAuth2ServiceConfiguration(serviceBindingCredentials, service);
	}

	private OAuth2ServiceConfiguration createOAuth2ServiceConfiguration(Map<String, String> serviceBindingCredentials,
			Service service) {
		OAuth2ServiceConfigurationBuilder builder = new OAuth2ServiceConfigurationBuilder();
		serviceBindingCredentials.forEach((key, value) -> builder.withProperty(key, value));
		return builder.withService(service).build();
	}

	/**
	 * Cloud Foundry specific information.
	 * 
	 * @return the CF service plan.
	 */
	public Plan getPlan() {
		if (plan == null) {
			String planAsString = serviceBindingProperties.get(SERVICE_PLAN);
			plan = planAsString != null ? Plan.from(planAsString) : Plan.DEFAULT;
		}
		return plan;
	}

	@Override public String getClientId() {
		return oAuth2ServiceConfiguration.getClientId();
	}

	@Override public String getClientSecret() {
		return oAuth2ServiceConfiguration.getClientSecret();
	}

	@Override public URI getUrl() {
		return oAuth2ServiceConfiguration.getUrl();
	}

	@Nullable @Override public String getProperty(String name) {
		return oAuth2ServiceConfiguration.getProperty(name);
	}

	@Override public boolean hasProperty(String name) {
		return oAuth2ServiceConfiguration.hasProperty(name);
	}

	@Override public Service getService() {
		return oAuth2ServiceConfiguration.getService();
	}
}
