/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import javax.annotation.Nullable;
import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * Represents xsuaa client identity
 */
public interface ClientIdentity {
	/**
	 * Client id of identity service instance.
	 *
	 * @return client identifier
	 */
	String getId();

	/**
	 * Returns true, if the mandatory attributes in ClientIdentity class are filled for the specified authentication
	 * method i.e X.509 or client secret
	 *
	 * @return the boolean
	 */
	default boolean isValid() {
		return false;
	}

	/**
	 * Returns true if ClientIdentity is certificate based.
	 *
	 * @return the boolean
	 */
	default boolean isCertificateBased() {
		return hasValue(getCertificate()) && hasValue(getKey()) ||
				getCertificateChain() != null && getPrivateKey() != null;
	}

	/**
	 * Client secret of identity service instance.
	 *
	 * @return client secret
	 */
	@Nullable
	default String getSecret() {
		return null;
	}

	/**
	 * PEM encoded certificate chain.
	 *
	 * @return certificate chain
	 */
	@Nullable
	default String getCertificate() {
		return null;
	}

	/**
	 * PEM encoded private key the certificate is signed with.
	 *
	 * @return private key
	 */
	@Nullable
	default String getKey() {
		return null;
	}

	/**
	 * @return Certificate chain array
	 */
	@Nullable
	default Certificate[] getCertificateChain() {
		return null;
	}

	/**
	 * @return Private key
	 */
	@Nullable
	default PrivateKey getPrivateKey() {
		return null;
	}

	static boolean hasValue(String value) {
		return value != null && !value.isEmpty();
	}

}
