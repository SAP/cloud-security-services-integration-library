/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.config;

import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;

/**
 * Central entry point to access the OAuth configuration
 * ({@link OAuth2ServiceConfiguration}) of a supported identity {@link Service}.
 */
public interface Environment {
	/**
	 * Return the primary OAuth service configuration of Xsuaa identity service
	 * instance.
	 *
	 * @return the OAuth service configuration or null, in case there is no instance
	 */
	@Nullable
	OAuth2ServiceConfiguration getXsuaaConfiguration();

	/**
	 * Return OAuth service configuration of IAS identity service instance.
	 *
	 * @return the OAuth service configuration or null, in case there is no instance
	 */
	@Nullable
	OAuth2ServiceConfiguration getIasConfiguration();

	/**
	 * Returns the number of Xsuaa identity service instances.
	 *
	 * @return the number Xsuaa identity service instances.
	 *
	 */
	int getNumberOfXsuaaConfigurations();

	/**
	 * In case there is only one Xsuaa identity service instance, this one gets
	 * returned. In case there are multiple bindings the primary one of plan
	 * "broker" gets returned.
	 *
	 * @return the service configuration to be used for token exchange
	 *
	 * @see <a href=
	 *      "https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/token-client/src/main/java/com/sap/cloud/security/xsuaa/tokenflows/XsuaaTokenFlows.java">com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows</a>
	 */
	@Nullable
	OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange();

	/**
	 * Gives access to all service configurations parsed from the environment.
	 *
	 * @return the service configurations grouped by service
	 */
	Map<Service, List<OAuth2ServiceConfiguration>> getServiceConfigurationsAsList();

	Map<Service, Map<ServiceConstants.Plan, OAuth2ServiceConfiguration>> getServiceConfigurations();
}
