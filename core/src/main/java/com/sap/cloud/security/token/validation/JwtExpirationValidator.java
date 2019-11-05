package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.core.DefaultTimeProvider;
import com.sap.cloud.security.core.TimeProvider;
import com.sap.cloud.security.token.Token;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;

public class JwtExpirationValidator implements Validator<Token> {

	public static final TemporalAmount CLOCK_SKEW_LEEWAY = Duration.ofMinutes(1);

	private final TemporalAmount clockSkewLeeway;
	private TimeProvider timeProvider;

	public JwtExpirationValidator() {
		this.timeProvider = new DefaultTimeProvider();
		clockSkewLeeway = CLOCK_SKEW_LEEWAY;
	}

	JwtExpirationValidator(TimeProvider timeProvider, TemporalAmount clockSkewLeeway) {
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
		String errorDescription = String.format("Jwt token expired at %s, time now: %s", expiration, now());
		return ValidationResults.createInvalid(errorDescription);
	}

	private Instant now() {
		return timeProvider.now();
	}

	private boolean isExpired(Instant expiration) {
		return expiration.plus(clockSkewLeeway).isAfter(now());
	}

}
