package com.sap.cloud.security.xsuaa.client;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

public class RequestParameterBuilder {

	private final Map<String, String> parameters = new HashMap<>();

	public RequestParameterBuilder withGrantType(String grantType) {
		parameters.put(GRANT_TYPE, grantType);
		return this;
	}

	public RequestParameterBuilder withClientId(String clientId) {
		parameters.put(PARAMETER_CLIENT_ID, clientId);
		return this;
	}

	public RequestParameterBuilder withRefreshToken(String refreshToken) {
		parameters.put(REFRESH_TOKEN, refreshToken);
		return this;
	}

	public RequestParameterBuilder withClientCredentials(ClientCredentials clientCredentials) {
		parameters.put(CLIENT_ID, clientCredentials.getId());
		parameters.put(CLIENT_SECRET, clientCredentials.getSecret());
		return this;
	}

	public RequestParameterBuilder withParameter(String name, String value) {
		if (parameters.containsKey(name)) {
			throw new IllegalArgumentException("Parameter '" + name + "' exists already.");
		}
		parameters.put(name, value);
		return this;
	}

	public RequestParameterBuilder withOptionalParameters(Map<String, String> optionalParameters) {
		Optional.ofNullable(optionalParameters).orElse(Collections.emptyMap())
				.forEach((key, value) -> parameters.putIfAbsent(key, value));
		return this;
	}

	public RequestParameterBuilder withUsername(String username) {
		parameters.put(USERNAME, username);
		return this;
	}

	public RequestParameterBuilder withPassword(String password) {
		parameters.put(PASSWORD, password);
		return this;
	}

	public RequestParameterBuilder withToken(String token) {
		parameters.put(ASSERTION, token);
		return this;
	}

	public Map<String, String> buildAsMap() {
		return parameters;
	}
}
