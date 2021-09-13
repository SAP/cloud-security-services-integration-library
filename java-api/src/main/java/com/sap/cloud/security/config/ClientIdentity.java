package com.sap.cloud.security.config;

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
	 * Returns true, if the mandatory attributes in ClientIdentity class are filled
	 * for the specified authentication method i.e X.509 or client secret
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
		return hasValue(getCertificate()) && hasValue(getKey());
	}

	/**
	 * Client secret of identity service instance.
	 *
	 * @return client secret
	 */
	default String getSecret() {
		return null;
	}

	/**
	 * PEM encoded certificate chain.
	 *
	 * @return certificate chain
	 */
	default String getCertificate() {
		return null;
	}

	/**
	 * PEM encoded private key the certificate is signed with.
	 *
	 * @return private key
	 */
	default String getKey() {
		return null;
	}

	static boolean hasValue(String value) {
		return value != null && !value.isEmpty();
	}

}
