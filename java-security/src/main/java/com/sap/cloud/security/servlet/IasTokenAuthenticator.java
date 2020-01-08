package com.sap.cloud.security.servlet;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;

public class IasTokenAuthenticator extends AbstractTokenAuthenticator {

	public IasTokenAuthenticator() {
		tokenKeyService = OAuth2TokenKeyServiceWithCache.getInstance();
		oidcConfigurationService = OidcConfigurationServiceWithCache.getInstance();
	}

	@Override
	public TokenExtractor getTokenExtractor() {
		return IasToken::new;
	}

	@Override
	protected Validator<Token> createTokenValidator() {
		return JwtValidatorBuilder
				.getInstance(Environments.getCurrent().getIasConfiguration())
				.withOAuth2TokenKeyService(tokenKeyService)
				.withOidcConfigurationService(oidcConfigurationService)
				.build();
	}

}
