package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;

import java.util.List;

public class XsuaaTokenAuthenticator extends AbstractTokenAuthenticator {

	public XsuaaTokenAuthenticator() {
		tokenKeyService = OAuth2TokenKeyServiceWithCache.getInstance();
		oidcConfigurationService = OidcConfigurationServiceWithCache.getInstance();
	}

	@Override
	public Token extractFromHeader(String authorizationHeader) {
		return new XsuaaToken(authorizationHeader)
				.withScopeConverter(getScopeConverter());
	}

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
		OAuth2ServiceConfiguration config =  serviceConfiguration != null ? serviceConfiguration :
				Environments.getCurrent().getXsuaaConfiguration();
		if(config == null) {
			throw new IllegalStateException("There must be a service configuration.");
		}
		return config;
	}

	@Override
	protected TokenAuthenticationResult authenticated(Token token) {
		List<String> translatedScopes = getScopeConverter()
				.convert(((XsuaaToken) token).getScopes());
		return TokenAuthenticationResult.createAuthenticated(translatedScopes, token);
	}

	private ScopeConverter getScopeConverter() {
		return new XsuaaScopeConverter(
				getServiceConfiguration().getProperty(CFConstants.XSUAA.APP_ID));
	}

}
