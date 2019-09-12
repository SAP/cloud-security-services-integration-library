package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;
import java.util.Objects;

import static com.sap.cloud.security.xsuaa.Assertions.*;

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
	public ClientCredentials(@Nonnull String clientId, @Nonnull String clientSecret) {
		assertNotNull(clientId, "clientId is required");
		assertNotNull(clientSecret, "clientSecret is required");
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

	@Override
	public String toString() {
		return String.format("%s:%s", clientId, clientSecret);
	}

}
