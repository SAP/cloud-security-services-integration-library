package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.core.DefaultTimeProvider;
import com.sap.cloud.security.core.TimeProvider;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;

public class JwtTimestampValidator implements Validator<Token> {

	private static final TemporalAmount DEFAULT_CLOCK_SKEW_LEEWAY = Duration.ofMinutes(1);

	private final TimeProvider timeProvider;
	private final TemporalAmount clockSkewLeeway;

	public JwtTimestampValidator() {
		timeProvider = new DefaultTimeProvider();
		clockSkewLeeway = DEFAULT_CLOCK_SKEW_LEEWAY;
	}

	JwtTimestampValidator(TimeProvider timeProvider, TemporalAmount clockSkewLeeway) {
		this.timeProvider = timeProvider;
		this.clockSkewLeeway = clockSkewLeeway;
	}

	@Override
	public ValidationResult validate(Token token) {
		ValidationResult validationResult = ValidationResults.createValid();

		Instant expiration = token.getExpiration();
		if (expiration != null) {
			 validationResult = checkExpiration(expiration);
		}

		Instant notBefore = token.getNotBefore();
		if (notBefore != null && validationResult.isValid()) {
			validationResult = checkNotBefore(notBefore);
		}

		return validationResult;
	}

	private ValidationResult checkExpiration(Instant expiration) {
		if (isNotExpired(expiration)) {
			return ValidationResults.createValid();
		}
		String errorDescription = String.format("Jwt expired at %s, time now: %s", expiration, now());
		return ValidationResults.createInvalid(errorDescription);

	}

	private ValidationResult checkNotBefore(Instant notBeforeTimestamp) {
		if (canBeAccepted(notBeforeTimestamp)) {
			return ValidationResults.createValid();
		}
		String errorDescription = String
				.format("Jwt cannot be accepted before %s, time now: %s", notBeforeTimestamp, now());
		return ValidationResults.createInvalid(errorDescription);
	}

	private boolean canBeAccepted(Instant notBeforeTimestamp) {
		return now().isAfter(notBeforeTimestamp.minus(clockSkewLeeway));
	}

	private boolean isNotExpired(Instant expiration) {
		return expiration.plus(clockSkewLeeway).isAfter(now());
	}

	private Instant now() {
		return timeProvider.now();
	}

}
