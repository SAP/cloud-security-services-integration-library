package com.sap.cloud.security.xsuaa.client;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public class ParameterBuilder {
	private final Map<String, String> parameters = new HashMap<>();

	public ParameterBuilder withGrantType(String grantType) {
		parameters.put(GRANT_TYPE, grantType);
		return this;
	}

	public ParameterBuilder withClientId(String clientId) {
		parameters.put(PARAMETER_CLIENT_ID, clientId);
		return this;
	}

	public Map<String, String> buildAsMap() {
		return parameters;
	}

	public ParameterBuilder withRefreshToken(String refreshToken) {
		parameters.put(REFRESH_TOKEN, refreshToken);
		return this;
	}

	public ParameterBuilder withClientCredentials(ClientCredentials clientCredentials) {
		parameters.put(CLIENT_ID, clientCredentials.getId());
		parameters.put(CLIENT_SECRET, clientCredentials.getSecret());
		return this;
	}

	public ParameterBuilder withAdditionalParameters(Map<String, String> optionalParameters) {
		Optional.ofNullable(optionalParameters).orElse(Collections.emptyMap())
				.forEach((key, value) -> parameters.putIfAbsent(key, value));
		return this;
	}

	public ParameterBuilder withUsername(String username) {
		parameters.put(USERNAME, username);
		return this;
	}

	public ParameterBuilder withPassword(String password) {
		parameters.put(PASSWORD, password);
		return this;
	}
}
