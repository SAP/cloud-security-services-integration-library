package com.sap.cloud.security.core.config;

import java.net.URI;

public interface OAuth2ServiceConfiguration {
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
	 * Base URL of the OAuth2 Identity service instance. In multi tenancy scenarios
	 * this is the url where the service instance was created.
	 *
	 * @return base url
	 */
	URI getUaaUrl();

	/**
	 * Domain of the uaa authentication domain
	 *
	 * @return uaaDomain
	 */
	String getUaaDomain();
}
