package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.core.DefaultTimeProvider;
import com.sap.cloud.security.core.TimeProvider;
import com.sap.cloud.security.token.Token;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;

public class JwtNotBeforeValidator implements Validator<Token> {

	public static final TemporalAmount CLOCK_SKEW_LEEWAY = Duration.ofMinutes(1);

	private final TemporalAmount clockSkewLeeway;
	private TimeProvider timeProvider;

	public JwtNotBeforeValidator() {
		this.timeProvider = new DefaultTimeProvider();
		clockSkewLeeway = CLOCK_SKEW_LEEWAY;
	}

	JwtNotBeforeValidator(TimeProvider timeProvider, TemporalAmount clockSkewLeeway) {
		this.timeProvider = timeProvider;
		this.clockSkewLeeway = clockSkewLeeway;
	}

	@Override
	public ValidationResult validate(Token token) {
		Instant notBefore = token.getNotBefore();
		return notBefore == null ? ValidationResults.createValid() : checkExpirationDate(notBefore);
	}

	private ValidationResult checkExpirationDate(Instant notBeforeTimestamp) {
		if (isAfter(notBeforeTimestamp)) {
			return ValidationResults.createValid();
		}
		String errorDescription = String
				.format("Jwt cannot be accepted before %s, time now: %s", notBeforeTimestamp, timeProvider.now());
		return ValidationResults.createInvalid(errorDescription);
	}

	private boolean isAfter(Instant notBeforeTimestamp) {
		return notBeforeTimestamp.minus(clockSkewLeeway).isAfter(timeProvider.now());
	}

}
