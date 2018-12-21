package com.sap.cloud.security.xsuaa;

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
	 * Base URL of the xsuaa service instance. In multi tenancy scenarios this is the
	 * url where the service instance was created.
	 * 
	 * @return uaa url
	 */
	String getUaaUrl();

	/**
	 * Url to the token_keys endpoint
	 * 
	 * @param zid
	 *            Zone Id (subaccount id)
	 * @param subdomain
	 *            of the subaccount
	 * @return
	 */
	String getTokenKeyUrl(String zid, String subdomain);

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
}