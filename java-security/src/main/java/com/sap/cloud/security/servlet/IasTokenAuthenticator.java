package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFEnvironment;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {

	@Override
	public Token extractFromHeader(String authorizationHeader) {
		return new IasToken(authorizationHeader);
	}

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
		return serviceConfiguration != null ? serviceConfiguration
				: ((CFEnvironment) Environments.getCurrent()).getIasConfiguration();
	}
}
