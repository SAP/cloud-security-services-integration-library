package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;

import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.xsuaa.Assertions.*;

public class CFOAuth2ServiceConfiguration implements OAuth2ServiceConfiguration {

	private final Service service;
	private final Map<String, String> credentials;
	private final Map<String, String> configuration;
	private Plan plan; // lazy read

	CFOAuth2ServiceConfiguration(Service service, Map<String, String> configuration, Map<String, String> credentials) {
		assertNotNull(configuration, "configuration must not be null");
		assertNotNull(credentials, "credentials must not be null");

		this.service = service;
		this.configuration = configuration;
		this.credentials = credentials;
	}

	@Override
	public String getClientId() {
		return credentials.get(CLIENT_ID);
	}

	@Override
	public String getClientSecret() {
		return credentials.get(CLIENT_SECRET);
	}

	@Override
	public URI getUrl() {
		return URI.create(credentials.get(URL));
	}

	@Override
	@Nullable
	public String getProperty(String name) {
		return credentials.get(name);
	}

	@Override
	public Service getService() {
		return this.service;
	}

	/**
	 * Cloud Foundry specific information.
	 * 
	 * @return the CF service plan.
	 */
	public Plan getPlan() {
		if (plan == null) {
			String planAsString = configuration.get(SERVICE_PLAN);
			plan = planAsString != null ? Plan.from(planAsString) : Plan.DEFAULT;
		}
		return plan;
	}

}
