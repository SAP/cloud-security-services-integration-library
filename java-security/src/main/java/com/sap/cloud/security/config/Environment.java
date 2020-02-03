package com.sap.cloud.security.config;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Central entry point to access the OAuth configuration
 * ({@link OAuth2ServiceConfiguration}) of a supported identity {@link Service}.
 */
public interface Environment {

	/**
	 * Represents a supported SAP CP environment.
	 */
	enum Type {
		CF /* , KUBERNETES */;
		public static Type from(String typeAsString) {
			return Type.valueOf(typeAsString.toUpperCase());
		}
	}

	@Nonnull
	Type getType();

	/**
	 * Return OAuth service configuration of Xsuaa identity service instance.
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
	OAuth2ServiceConfiguration getIasConfiguration(); // TODO IAS

	/**
	 * Returns number of Xsuaa identity service instances.
	 *
	 * @return the number Xsuaa identity service instances.
	 *
	 */
	int getNumberOfXsuaaConfigurations();

	/**
	 * In case there is only one Xsuaa identity service instance, this one gets
	 * returned. In case there are multiple bindings the one of plan "broker" gets
	 * returned.
	 *
	 * @return the service configuration to be used for token exchange
	 *         {@link com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows}
	 */
	@Nullable
	OAuth2ServiceConfiguration getXsuaaConfigurationForTokenExchange();

}
