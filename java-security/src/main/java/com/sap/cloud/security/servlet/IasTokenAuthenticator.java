package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {

	@Override
	public Token extractFromHeader(String authorizationHeader) {
		return new IasToken(authorizationHeader);
	}

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
		OAuth2ServiceConfiguration config = serviceConfiguration != null ? serviceConfiguration
				: Environments.getCurrent().getIasConfiguration();
		if (config == null) {
			throw new IllegalStateException("There must be a service configuration.");
		}
		return config;
	}
}
