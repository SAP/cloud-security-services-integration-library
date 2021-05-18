package com.sap.cloud.security.xsuaa;

import javax.annotation.Nullable;

public interface XsuaaServiceConfiguration {
	/**
	 * Client id of xsuaa service instance
	 * 
	 * @return clientId
	 */
	String getClientId();

	/**
	 * Client secret of xsuaa instance
	 * 
	 * @return client secret
	 */
	String getClientSecret();

	/**
	 * Base URL of the xsuaa service instance. In multi tenancy scenarios this is
	 * the url where the service instance was created.
	 * 
	 * @return uaa url
	 */
	String getUaaUrl();

	/**
	 * Base certificate URL of the xsuaa service instance.
	 *
	 * @return uaa mTLS url
	 */
	@Nullable
	String getUaaCertUrl();

	/**
	 * Defined Credential type of the xsuaa service instance.
	 * @return
	 */
	String getCredentialType();

	/**
	 * XS application identifier
	 * 
	 * @return xs application id
	 */
	String getAppId();

	/**
	 * Domain of the xsuaa authentication domain
	 * 
	 * @return uaaDomain
	 */
	String getUaaDomain();

	/**
	 * The pem encoded public key for offline token verification.
	 *
	 * @return the pem encoded verification key
	 */
	@Nullable
	String getVerificationKey();

	/**
	 * PEM encoded certificate chain.
	 *
	 * @return certificates
	 */
	 @Nullable
	 String getCertificates();

	/**
	 * Private key the certificate is signed with.
	 *
	 * @return private key
	 */
	 @Nullable
	 String getPrivateKey();
}