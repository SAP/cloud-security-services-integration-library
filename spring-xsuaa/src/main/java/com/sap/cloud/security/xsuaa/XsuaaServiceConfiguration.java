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
	 * Base URL of the xsuaa service instance. In multi tenancy scenarios this is
	 * the url where the service instance was created.
	 * 
	 * @return uaa url
	 */
	String getUaaUrl();

	/**
	 * Url to the token_keys endpoint
	 * 
	 * @param identityZoneId
	 *            Identity Zone Id (subaccount id)
	 * @param subdomain
	 *            of the subaccount
	 * @return token key endpoint
	 *
	 * @deprecated Xsuaa version 2.8.0 provides jwt token key url (jku) as part of
	 *             the JWT. This method gets deleted with version 2.0.0.
	 */
	@Deprecated
	String getTokenKeyUrl(String identityZoneId, String subdomain);

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