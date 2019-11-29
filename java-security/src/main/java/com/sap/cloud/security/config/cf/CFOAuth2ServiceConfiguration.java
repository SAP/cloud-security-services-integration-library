package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;

import javax.annotation.Nullable;
import java.net.URI;

import static com.sap.cloud.security.config.cf.CFConstants.*;
import static com.sap.cloud.security.xsuaa.Assertions.*;

public class CFOAuth2ServiceConfiguration implements OAuth2ServiceConfiguration {

	private final Service service;
	private final JsonObject credentials;
	private final JsonObject configuration;
	private Plan plan; // lazy read

	CFOAuth2ServiceConfiguration(Service service, JsonObject jsonServiceConfiguration) {
		assertNotNull(service, "service must not be null");
		assertNotNull(jsonServiceConfiguration, "jsonServiceConfiguration must not be null");

		this.service = service;
		this.configuration = jsonServiceConfiguration;
		this.credentials = configuration.getJsonObject(CREDENTIALS);
	}

	@Override
	public String getClientId() {
		return service.equals(Service.XSUAA) ? credentials.getAsString(XSUAA.CLIENT_ID)
				: credentials.getAsString(IAS.CLIENT_ID);
	}

	@Override
	public String getClientSecret() {
		return service.equals(Service.XSUAA) ? credentials.getAsString(XSUAA.CLIENT_SECRET)
				: credentials.getAsString(IAS.CLIENT_SECRET);
	}

	@Override
	public URI getUrl() {
		return URI.create(credentials.getAsString(URL));
	}

	@Nullable
	@Override
	public String getDomain() {
		return service.equals(Service.XSUAA) ? credentials.getAsString(XSUAA.UAA_DOMAIN)
				: credentials.getAsString(IAS.DOMAIN);
	}

	@Override
	@Nullable
	public String getProperty(String name) {
		return credentials.getAsString(name);
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
			String planAsString = configuration.getAsString(SERVICE_PLAN);
			plan = planAsString != null ? Plan.from(planAsString) : Plan.DEFAULT;
		}
		return plan;
	}

}
