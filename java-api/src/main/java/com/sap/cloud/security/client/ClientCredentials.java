/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.xsa.security.container.ClientIdentity;

import javax.annotation.Nonnull;
import java.util.Objects;

public class ClientCredentials implements ClientIdentity {
	private static final long serialVersionUID = 2405162041950251807L;

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
		assertHasText(clientId, "clientId must not be empty");
		assertHasText(clientSecret, "clientSecret must not be empty");
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	@Override
	public String getSecret() {
		return clientSecret;
	}

	@Override
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

	private static void assertNotNull(Object object, String message) {
		if (object == null) {
			throw new IllegalArgumentException(message);
		}
	}

	private static void assertHasText(String string, String message) {
		if (string == null || string.trim().isEmpty()) {
			throw new IllegalArgumentException(message);
		}
	}
}
