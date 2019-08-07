package com.sap.cloud.security.xsuaa.backend;

public class ClientCredentials {

	private final String clientSecret;
	private final String clientId;

	public ClientCredentials(String clientId, String clientSecret) {
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
