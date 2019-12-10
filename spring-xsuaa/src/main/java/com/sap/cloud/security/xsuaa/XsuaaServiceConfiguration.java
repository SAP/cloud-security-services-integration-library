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
	 * PEM encoded certificate chain.
	 *
	 * @return certificates
	 */
	//@Nullable
	//String getCertificates();

	/**
	 * Private key the certificate is signed with.
	 *
	 * @return private key
	 */
	//@Nullable
	//String getPrivateKey();
}