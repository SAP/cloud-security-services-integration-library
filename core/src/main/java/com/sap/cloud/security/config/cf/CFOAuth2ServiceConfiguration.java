package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.json.JsonObject;

import javax.annotation.Nullable;
import java.net.URI;

import static com.sap.cloud.security.config.cf.CFConstants.*;

public class CFOAuth2ServiceConfiguration implements OAuth2ServiceConfiguration {

	private final JsonObject credentials;
	private final JsonObject configuration;

	CFOAuth2ServiceConfiguration(JsonObject configuration) {
		this.credentials = configuration.getJsonObject(CREDENTIALS);
		this.configuration = configuration;
	}

	@Override
	public String getClientId() {
		return credentials.getAsString(CLIENT_ID);
	}

	@Override
	public String getClientSecret() {
		return credentials.getAsString(CLIENT_SECRET);
	}

	@Override
	public URI getUrl() {
		return URI.create(credentials.getAsString(URL));
	}

	@Nullable
	@Override
	public String getDomain() {
		return credentials.getAsString(UAA_DOMAIN);
	}

	@Override
	@Nullable
	public String getProperty(String name) {
		return credentials.getAsString(name);
	}

	@Nullable
	public Plan getPlan() {
		String planAsString = configuration.getAsString(SERVICE_PLAN);
		return planAsString != null ? Plan.from(planAsString) : null;
	}

}
