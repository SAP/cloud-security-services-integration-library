package com.sap.cloud.security.token.validation.validators.timestamp;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.token.validation.validators.CombiningValidator;

import java.time.Duration;
import java.time.temporal.TemporalAmount;

public class JwtTimestampValidator implements Validator<Token> {

	public static final TemporalAmount CLOCK_SKEW_LEEWAY = Duration.ofMinutes(1);
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
