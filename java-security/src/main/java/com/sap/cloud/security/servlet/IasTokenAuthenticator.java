package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.SapIdToken;
import com.sap.cloud.security.token.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {

	private static final Logger LOGGER = LoggerFactory.getLogger(IasTokenAuthenticator.class);

	public IasTokenAuthenticator(){
		LOGGER.warn("IAS Service is not yet supported!");
	}

	@Override
	public Token extractFromHeader(String authorizationHeader) {
		return new SapIdToken(authorizationHeader);
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

	@Nullable
	@Override
	protected OAuth2ServiceConfiguration getOtherServiceConfiguration() {
		return null;
	}
}
