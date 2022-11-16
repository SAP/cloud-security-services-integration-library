/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import javax.annotation.Nonnull;
import java.io.Serializable;
import java.util.Objects;

public class ClientCredentials implements ClientIdentity, Serializable {
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
	public boolean isValid() {
		return !isCertificateBased() && ClientIdentity.hasValue(clientId) && ClientIdentity.hasValue(clientSecret);
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
