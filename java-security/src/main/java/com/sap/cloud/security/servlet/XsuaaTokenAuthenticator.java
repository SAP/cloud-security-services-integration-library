package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.token.*;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;

import javax.annotation.Nullable;
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
	protected Validator<Token> createTokenValidator() {
			return JwtValidatorBuilder
					.getInstance(Environments.getCurrent().getXsuaaConfiguration())
					.withOAuth2TokenKeyService(tokenKeyService)
					.withOidcConfigurationService(oidcConfigurationService)
					.configureAnotherServiceInstance(getOtherXsuaaServiceConfiguration())
					.build();
	}

	private class XsuaaTokenExtractor implements TokenExtractor {
		@Override
		public Token from(String authorizationHeader) {
			if (Environments.getCurrent().getXsuaaConfiguration() != null) {
				return new XsuaaToken(authorizationHeader,
						Environments.getCurrent().getXsuaaConfiguration().getProperty(CFConstants.XSUAA.APP_ID));
			}
			throw new RuntimeException("XsuaaConfiguration not found. Are VCAP_SERVICES missing?");
		}
	}

	@Nullable
	private OAuth2ServiceConfiguration getOtherXsuaaServiceConfiguration() {
		if (Environments.getCurrent().getNumberOfXsuaaConfigurations() > 1) {
			return Environments.getCurrent().getXsuaaConfigurationForTokenExchange();
		}
		return null;
	}

	@Override
	protected TokenAuthenticationResult authenticated(Token token) {
		if (token.getService() != Service.XSUAA) {
		 	return super.authenticated(token);
		}
		List<String> scopes = token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
		List<String> translatedScopes = new XsuaaScopeTranslator().translateToLocalScope(scopes);
		return TokenAuthenticationResult.authenticated(translatedScopes, token);
	}

}
