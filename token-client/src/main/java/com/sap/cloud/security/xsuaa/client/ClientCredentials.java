package com.sap.cloud.security.xsuaa.client;

import org.springframework.lang.NonNull;
import org.springframework.util.Assert;

public class ClientCredentials {

	private final String clientSecret;
	private final String clientId;

	public ClientCredentials(@NonNull String clientId, @NonNull String clientSecret) {
		Assert.notNull(clientId, "clientId is required");
		Assert.notNull(clientSecret, "clientSecret is required");
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public String getClientId() {
		return clientId;
	}
}
