/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;

import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;

public interface XsuaaServiceConfiguration extends OAuth2ServiceConfiguration {

	/**
	 * Base URL of the xsuaa service instance. In multi tenancy scenarios this is
	 * the url where the service instance was created.
	 * 
	 * @return uaa url
	 */
	String getUaaUrl();

	@Override
	default URI getUrl() {
		return URI.create(getUaaUrl());
	}

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

	@Nullable
	@Override
	default String getProperty(String name) {
		throw new UnsupportedOperationException("getProperty method is not supported");
	}

	@Override
	default Map<String, String> getProperties() {
		throw new UnsupportedOperationException("getProperties method is not supported");
	}

	@Override
	default boolean hasProperty(String name) {
		throw new UnsupportedOperationException("hasProperty method is not supported");
	}

	@Override
	default ClientIdentity getClientIdentity() {
		throw new UnsupportedOperationException(
				"This default method needs to be overridden to be used! Default method from " +
						"com.sap.cloud.security.config.OAuth2ServiceConfiguration#getClientIdentity() " +
						"is not compatible with XsuaaServiceConfiguration interface");
	}

	@Override
	default Service getService() {
		throw new UnsupportedOperationException("getService method is not supported");
	}

	@Override
	default boolean isLegacyMode() {
		throw new UnsupportedOperationException("isLegacyMode method is not supported");
	}
}