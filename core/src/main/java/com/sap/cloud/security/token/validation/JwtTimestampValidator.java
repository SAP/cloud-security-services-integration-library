package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.core.DefaultTimeProvider;
import com.sap.cloud.security.core.TimeProvider;
import com.sap.cloud.security.token.Token;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;

public class JwtTimestampValidator implements Validator<Token> {

	public static final TemporalAmount CLOCK_SKEW_LEEWAY = Duration.ofMinutes(1);

	private final TemporalAmount clockSkewLeeway;
	private TimeProvider timeProvider;

	public JwtTimestampValidator() {
		this.timeProvider = new DefaultTimeProvider();
		clockSkewLeeway = CLOCK_SKEW_LEEWAY;
	}

	JwtTimestampValidator(TimeProvider timeProvider, TemporalAmount clockSkewLeeway) {
		this.timeProvider = timeProvider;
		this.clockSkewLeeway = clockSkewLeeway;
	}

	@Override
	public ValidationResult validate(Token token) {
		Instant expiration = token.getExpiration();
		return expiration == null ? ValidationResults.createValid() : checkExpirationDate(expiration);
	}

	private ValidationResult checkExpirationDate(Instant expiration) {
		if (isExpired(expiration)) {
			return ValidationResults.createValid();
		}
		String errorDescription = String.format("Jwt token expired at %s, time now: %s", expiration, timeProvider.now());
		return ValidationResults.createInvalid(errorDescription);
	}

	private boolean isExpired(Instant expiration) {
		return expiration.plus(clockSkewLeeway).isAfter(timeProvider.now());
	}

}
