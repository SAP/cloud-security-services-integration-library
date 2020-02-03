package com.sap.cloud.security.config;

import javax.annotation.Nullable;

import java.net.URI;

/**
 * Provides information of the identity {@link Service}.
 */
public interface OAuth2ServiceConfiguration {

	/**
	 * Client id of identity service instance.
	 *
	 * @return client identifier
	 */
	String getClientId();

	/**
	 * Client secret of identity service instance.
	 *
	 * @return client secret
	 */
	String getClientSecret();

	/**
	 * Base URL of the OAuth2 identity service instance. In multi tenancy scenarios
	 * this is the url where the service instance was created.
	 *
	 * @return base url, e.g. https://paastenant.idservice.com
	 */
	URI getUrl();

	/**
	 * Returns the value of the given property as string.
	 *
	 * @param name
	 *            the name of the property. You can find constants in
	 *            {@link com.sap.cloud.security.config.cf.CFConstants}
	 * @return the string value of the given property or null if the property does
	 *         not exist.
	 */
	@Nullable
	String getProperty(String name);

	/**
	 * Returns true if the configuration contains the given property.
	 *
	 * @param name
	 *            the name of the property. You can find constants in
	 *            {@link com.sap.cloud.security.config.cf.CFConstants}
	 * @return true if the property does not exist.
	 */
	boolean hasProperty(String name);

	/**
	 * Returns the identity {@link Service} of this configuration.
	 *
	 * @return the service.
	 */
	Service getService();

	/**
	 * Domain (without subdomain) of identity service instance.
	 *
	 * @return domain
	 */
	String getDomain();

	/**
	 * Returns true, in case of XSUAA service runs in legacy mode.
	 *
	 * @return true in case it runs in legacy mode.
	 */
	boolean isLegacyMode();
}
