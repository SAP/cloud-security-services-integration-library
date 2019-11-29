package com.sap.cloud.security.config;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface Environment {

	enum Type {
		CF /* , KUBERNETES */;
		public static Type from(String typeAsString) {
			return Type.valueOf(typeAsString.toUpperCase());
		}
	}

	@Nonnull
	Type getType();

	@Nullable
	OAuth2ServiceConfiguration getXsuaaServiceConfiguration();

	@Nullable
	OAuth2ServiceConfiguration getIasServiceConfiguration();

	/**
	 * @deprecated as multiple bindings of identity service is not anymore necessary
	 *             with the unified broker plan, this method is deprecated.
	 */
	@Deprecated
	int getNumberOfXsuaaServices();

	/**
	 * In case there is only one binding, this gets returned. In case there are
	 * multiple bindings the one of plan "broker" gets returned.
	 *
	 * @return the service configuration to be used for token exchange
	 *         {@link com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows}
	 * @deprecated as multiple bindings of identity service is not anymore necessary
	 *             with the unified broker plan, this method is deprecated.
	 */
	@Deprecated
	@Nullable
	OAuth2ServiceConfiguration getXsuaaServiceConfigurationForTokenExchange();

}
