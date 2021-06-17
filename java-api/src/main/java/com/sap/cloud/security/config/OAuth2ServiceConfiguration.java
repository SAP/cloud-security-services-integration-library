/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import javax.annotation.Nullable;

import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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
	 * Client Identity of xsuaa instance
	 * 
	 * @return ClientIdentity object
	 */
	default ClientIdentity getClientIdentity() {
		return new ClientCredentials(getClientId(), getClientSecret());
	}

	/**
	 * Credential type as defined in "oauth2-configuration" of the xsuaa service
	 * instance security descriptor.
	 * 
	 * @return value of credential-type field
	 */
	default CredentialType getCredentialType(){ return null; }

	/**
	 * Base URL of the OAuth2 identity service instance. In multi tenancy scenarios
	 * this is the url where the service instance was created.
	 *
	 * @return base url, e.g. https://paastenant.idservice.com
	 */
	URI getUrl();

	/**
	 * Cert URL of the OAuth2 identity service instance.
	 *
	 * @return cert url, e.g. https://paastenant.cert.idservice.com
	 */
	default URI getCertUrl(){
		return null;
	}

	/**
	 * Domains of the OAuth2 identity service instance.
	 *
	 * @return list of domain, e.g."idservice.com".
	 */
	default List<String> getDomains(){ return Collections.emptyList(); }

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
	 * Returns all properties of the configuration as a map.
	 * 
	 * @return all properties as map.
	 */
	Map<String, String> getProperties();

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
	 * Returns true, in case of XSUAA service runs in legacy mode.
	 *
	 * @return true in case it runs in legacy mode.
	 */
	boolean isLegacyMode();
}
