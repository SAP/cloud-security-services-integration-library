package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.core.Assertions;
import com.sap.cloud.security.core.DefaultTimeProvider;
import com.sap.cloud.security.core.TimeProvider;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;

/**
 * Checks whether the jwt token is used before the "expiration (exp)" time and
 * if it is used after the "not before (nbf)" time.
 *
 * See specification:
 * https://tools.ietf.org/html/rfc7519#section-4.1.4
 * https://tools.ietf.org/html/rfc7519#section-4.1.5
 */
public class JwtTimestampValidator implements Validator<Token> {

	/**
	 * Implementers MAY provide for some small leeway, usually no more than
	 * a few minutes, to account for clock skew.
	 */
	private static final TemporalAmount DEFAULT_TOLERANCE = Duration.ofMinutes(1);

	private final TimeProvider timeProvider;
	private final TemporalAmount tolerance;

	public JwtTimestampValidator() {
		this(new DefaultTimeProvider(), DEFAULT_TOLERANCE);
	}

	JwtTimestampValidator(TimeProvider timeProvider, TemporalAmount tolerance) {
		Assertions.assertNotNull(timeProvider, "timeProvider must not be null");
		Assertions.assertNotNull(tolerance, "tolerance must not be null");

	    this.timeProvider = timeProvider;
		this.tolerance = tolerance;
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
		return now().isAfter(notBeforeTimestamp.minus(tolerance));
	}

	private boolean isNotExpired(Instant expiration) {
		return expiration.plus(tolerance).isAfter(now());
	}

	private Instant now() {
		return timeProvider.now();
	}

}
