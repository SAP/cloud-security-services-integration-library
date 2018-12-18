package com.sap.cloud.security.xsuaa;

public interface XsuaaServiceConfiguration {
	/**
	 * Client id of xsuaa service instance
	 * 
	 * @return
	 */
	String getClientId();

	/**
	 * Client secret of xsuaa instance
	 * 
	 * @return
	 */
	String getClientSecret();

	/**
	 * URL of the xsuaa service instance. In multi tenancy scenarios this is the
	 * url where the service instance was created.
	 * 
	 * @return
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
	 * XSAppid.
	 * 
	 * @return
	 */
	String getAppId();

	/**
	 * Domain of the xsuaa authentication domain
	 * 
	 * @return
	 */
	String getUaadomain();
}