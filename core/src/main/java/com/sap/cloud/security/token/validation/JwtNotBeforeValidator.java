package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.core.DefaultTimeProvider;
import com.sap.cloud.security.core.TimeProvider;
import com.sap.cloud.security.token.Token;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;

public class JwtNotBeforeValidator implements Validator<Token> {

	public static final TemporalAmount CLOCK_SKEW_LEEWAY = Duration.ofMinutes(1);

	private final TemporalAmount clockSkewLeeway;
	private final TimeProvider timeProvider;

	public JwtNotBeforeValidator() {
		timeProvider = new DefaultTimeProvider();
		clockSkewLeeway = CLOCK_SKEW_LEEWAY;
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
		if (now().isAfter(notBeforeTimestamp) || now().equals(notBeforeTimestamp)) {
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
