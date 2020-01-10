package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;

import java.util.List;

public class XsuaaTokenAuthenticator extends AbstractTokenAuthenticator {

	private final TokenExtractor xsuaaTokenExtractor = new XsuaaTokenExtractor();

	public XsuaaTokenAuthenticator() {
		tokenKeyService = OAuth2TokenKeyServiceWithCache.getInstance();
		oidcConfigurationService = OidcConfigurationServiceWithCache.getInstance();
	}

	@Override
	public TokenExtractor getTokenExtractor() {
		return xsuaaTokenExtractor;
	}

	@Override
	protected OAuth2ServiceConfiguration getServiceConfiguration() {
		return serviceConfiguration != null ? serviceConfiguration : Environments.getCurrent().getXsuaaConfiguration();
	}

	private TokenScopeConverter getScopeConverter() {
		return new XsuaaScopeConverter(
				getServiceConfiguration().getProperty(CFConstants.XSUAA.APP_ID));
	}

	private class XsuaaTokenExtractor implements TokenExtractor {
		@Override
		public Token from(String authorizationHeader) {
			return new XsuaaToken(authorizationHeader)
					.withScopeConverter(getScopeConverter());
		}
	}

	@Override
	protected TokenAuthenticationResult authenticated(Token token) {
		List<String> translatedScopes = getScopeConverter()
											.convert(((XsuaaToken) token).getScopes());
		return TokenAuthenticationResult.createAuthenticated(translatedScopes, token);
	}

}
