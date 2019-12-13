package com.sap.cloud.security.samples.ias;

import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.servlet.DefaultTokenAuthenticator;
import com.sap.cloud.security.token.IasToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;
import com.sap.cloud.security.token.validation.validators.JwtValidatorBuilder;

public class IasTokenAuthenticator extends DefaultTokenAuthenticator {

	private CombiningValidator<Token> tokenValidator;

	@Override
	public TokenExtractor getTokenExtractor() {
		return (authorizationHeader) -> new IasToken(authorizationHeader);
	}

	@Override
	protected Validator<Token> getOrCreateTokenValidator() {
		if (tokenValidator == null) {
			tokenValidator = JwtValidatorBuilder
					.getInstance(Environments.getCurrent().getIasConfiguration())
					//.withOAuth2TokenKeyService(tokenKeyService)
					//.withOidcConfigurationService(oidcConfigurationService)
					.build();
		}
		return tokenValidator;
	}

}
