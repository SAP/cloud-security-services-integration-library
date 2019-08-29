package com.sap.cloud.security.xsuaa.client;

import org.springframework.lang.NonNull;
import org.springframework.util.Assert;

import java.util.Objects;

public class ClientCredentials {

	private final String clientSecret;
	private final String clientId;

	/**
	 * Specifies the OAuth 2.0 client.<br>
	 *
	 * @param clientId
	 *            - the ID of the OAuth 2.0 client requesting the token.
	 * @param clientSecret
	 *            - the secret of the OAuth 2.0 client requesting the token.
	 */
	public ClientCredentials(@NonNull String clientId, @NonNull String clientSecret) {
		Assert.notNull(clientId, "clientId is required");
		Assert.notNull(clientSecret, "clientSecret is required");
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	public String getSecret() {
		return clientSecret;
	}

	public String getId() {
		return clientId;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		ClientCredentials that = (ClientCredentials) o;
		return Objects.equals(clientSecret, that.clientSecret) &&
				Objects.equals(clientId, that.clientId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(clientSecret, clientId);
	}
}
