package com.sap.cloud.security.token.validation.validators.timestamp;

import com.sap.cloud.security.core.DefaultTimeProvider;
import com.sap.cloud.security.core.TimeProvider;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import java.time.Instant;
import java.time.temporal.TemporalAmount;

public class JwtNotBeforeValidator implements Validator<Token> {

	private final TemporalAmount clockSkewLeeway;
	private final TimeProvider timeProvider;

	public JwtNotBeforeValidator() {
		timeProvider = new DefaultTimeProvider();
		clockSkewLeeway = JwtTimestampValidator.CLOCK_SKEW_LEEWAY;
	}

	JwtNotBeforeValidator(TimeProvider timeProvider, TemporalAmount clockSkewLeeway) {
		this.timeProvider = timeProvider;
		this.clockSkewLeeway = clockSkewLeeway;
	}

	@Override
	public ValidationResult validate(Token token) {
		Instant notBefore = token.getNotBefore();
		return notBefore == null ? ValidationResults.createValid() : checkNotBefore(notBefore);
	}

	private ValidationResult checkNotBefore(Instant notBeforeTimestamp) {
		if (now().isAfter(notBeforeTimestamp.minus(clockSkewLeeway))) {
			return ValidationResults.createValid();
		}
		String errorDescription = String
				.format("Jwt cannot be accepted before %s, time now: %s", notBeforeTimestamp, now());
		return ValidationResults.createInvalid(errorDescription);
	}

	private Instant now() {
		return timeProvider.now();
	}

}
