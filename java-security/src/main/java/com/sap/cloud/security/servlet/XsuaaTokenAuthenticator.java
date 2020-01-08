package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
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

	private class XsuaaTokenExtractor implements TokenExtractor {
		@Override
		public Token from(String authorizationHeader) {
			if (getServiceConfiguration() != null) {
				return new XsuaaToken(authorizationHeader,
						getServiceConfiguration().getProperty(CFConstants.XSUAA.APP_ID));
			}
			throw new RuntimeException("XsuaaConfiguration not found. Are VCAP_SERVICES missing?");
		}
	}

	@Override
	protected TokenAuthenticationResult authenticated(Token token) {
		if (token.getService() != Service.XSUAA) {
			return super.authenticated(token);
		}
		List<String> scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
		List<String> translatedScopes = new XsuaaScopeTranslator(
				getServiceConfiguration().getProperty(CFConstants.XSUAA.APP_ID)).toLocalScope(scopes);
		return TokenAuthenticationResult.createAuthenticated(translatedScopes, token);
	}

}
