package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.TemporalAmount;

import static java.time.ZoneOffset.*;
import static java.time.temporal.ChronoUnit.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

public class JwtExpirationValidatorTest {

	private static final TemporalAmount CLOCK_SKEW_LEEWAY = Duration.ofMinutes(1);
	private static final Instant NOW = LocalDate.of(2019, 3, 3).atStartOfDay().toInstant(UTC);
	private JwtExpirationValidator cut;

	@Before
	public void setUp() {
		cut = new JwtExpirationValidator(() -> NOW, CLOCK_SKEW_LEEWAY);
	}

	@Test
	public void tokenLacksExpiration_isValid() {
		Token token = createTokenWithExpirationAt(null);

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenExpiredYesterday_isNotValidAndContainsErrorDescriptionWithDates() {
		Instant expiration = NOW.minus(1, DAYS);
		Token token = createTokenWithExpirationAt(expiration);

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String description = validationResult.getErrors().get(0).getDescription();
		assertThat(description).contains(NOW.toString()).contains(expiration.toString());
	}

	@Test
	public void tokenExpiresTomorrow_isValid() {
		Token token = createTokenWithExpirationAt(NOW.plus(1, DAYS));

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenExpiredLongerThanClockSkewLeeway_isNotValid() {
		Token token = createTokenWithExpirationAt(NOW.minus(CLOCK_SKEW_LEEWAY));

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
	}

	@Test
	public void tokenExpiredButJustInClockSkewLeeway_isValid() {
		Token token = createTokenWithExpirationAt(NOW.minus(CLOCK_SKEW_LEEWAY).plus(1, SECONDS));

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	private Token createTokenWithExpirationAt(Instant dateInstant) {
		Token token = Mockito.mock(Token.class);
		when(token.getExpiration()).thenReturn(dateInstant);
		return token;
	}
}