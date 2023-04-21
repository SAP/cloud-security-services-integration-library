/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import javax.annotation.Nullable;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.function.Supplier;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;

/**
 * Validates whether the jwt access token is used before the "expiration"
 * ({@code exp}) time and if it is used after the "not before" ({@code nbf})
 * time.
 * <p>
 * See specification: <a href=https://tools.ietf.org/html/rfc7519#section-4.1.4>https://tools.ietf.org/html/rfc7519#section-4.1.4</a>
 * <a href=https://tools.ietf.org/html/rfc7519#section-4.1.5>https://tools.ietf.org/html/rfc7519#section-4.1.5</a>
 */
class JwtTimestampValidator implements Validator<Token> {

	/**
	 * Implementers MAY provide for some small leeway, usually no more than a few
	 * minutes, to account for clock skew.
	 */
	private static final TemporalAmount DEFAULT_TOLERANCE = Duration.ofMinutes(1);

	private final Supplier<Instant> timeProvider;
	private final TemporalAmount tolerance;

	JwtTimestampValidator() {
		this(Instant::now, DEFAULT_TOLERANCE);
	}

	/**
	 * For testing only!
	 */
	JwtTimestampValidator(Supplier<Instant> timeProvider, @Nullable TemporalAmount tolerance) {
		this.timeProvider = timeProvider;
		this.tolerance = tolerance != null ? tolerance : DEFAULT_TOLERANCE;
	}

	@Override
	public ValidationResult validate(Token token) {
		ValidationResult validationResult;

		Instant expiration = token.getExpiration();
		if (expiration != null) {
			validationResult = checkExpiration(expiration);
		} else {
			return ValidationResults.createInvalid("Jwt does not contain expiration (exp) claim. Cannot be validated!");
		}

		Instant notBefore = token.getNotBefore(); // considers "iat" as well
		if (notBefore != null && validationResult.isValid()) {
			validationResult = checkNotBefore(notBefore);
		}

		return validationResult;
	}

	private ValidationResult checkExpiration(Instant expiration) {
		if (isNotExpired(expiration)) {
			return ValidationResults.createValid();
		}
		return createInvalid("Jwt expired at {}, time now: {}", expiration, now());

	}

	private ValidationResult checkNotBefore(Instant notBeforeTimestamp) {
		if (canBeAccepted(notBeforeTimestamp)) {
			return ValidationResults.createValid();
		}
		return createInvalid("Jwt cannot be accepted before {}, time now: {}", notBeforeTimestamp, now());
	}

	private boolean canBeAccepted(Instant notBeforeTimestamp) {
		return now().isAfter(notBeforeTimestamp.minus(tolerance));
	}

	private boolean isNotExpired(Instant expiration) {
		return expiration.plus(tolerance).isAfter(now());
	}

	private Instant now() {
		return timeProvider.get();
	}

}
