package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;

public class JwtTimestampValidator implements Validator<Token> {

	private CombiningValidator<Token> combinedValidator;

	public JwtTimestampValidator() {
		combinedValidator = CombiningValidator.builderFor(Token.class)
				.with(new JwtExpirationValidator())
				.with(new JwtNotBeforeValidator()).build();
	}
	@Override
	public ValidationResult validate(Token token) {
		return combinedValidator.validate(token);
	}

}
