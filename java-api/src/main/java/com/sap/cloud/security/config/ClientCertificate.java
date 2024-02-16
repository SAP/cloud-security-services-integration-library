/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import javax.annotation.Nullable;
import java.util.Objects;

public class ClientCertificate implements ClientIdentity {

	private final String certificate;
	private final String key;
	private final String clientId;

	/**
	 * Represents certificate based client identity.
	 *
	 * @param certificate
	 * 		PEM encoded X.509 certificate of the OAuth 2.0 client
	 * @param key
	 * 		PEM encoded X.509 private key of the OAuth 2.0 client
	 * @param clientId
	 * 		ID of the OAuth 2.0 client requesting the token.
	 */
	public ClientCertificate(@Nullable String certificate, @Nullable String key, @Nullable String clientId) {
		this.certificate = certificate;
		this.key = key;
		this.clientId = clientId;
	}

	@Override
	public String getCertificate() {
		return certificate;
	}

	@Override
	public String getKey() {
		return key;
	}

	@Override
	public String getId() {
		return clientId;
	}

	@Override
	public boolean isValid() {
		return ClientIdentity.hasValue(clientId) && isCertificateBased();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (!(o instanceof ClientCertificate that))
			return false;
		return Objects.requireNonNull(certificate, "certificate must be provided").equals(that.certificate) &&
				Objects.requireNonNull(key, "key must be provided").equals(that.key) &&
				Objects.requireNonNull(clientId, "clientId must be provided").equals(that.clientId);
	}

	@Override
	public int hashCode() {
		return Objects.hash(certificate, key, clientId);
	}

}
