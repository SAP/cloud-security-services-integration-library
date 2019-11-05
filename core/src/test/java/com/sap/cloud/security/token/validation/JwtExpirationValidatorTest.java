package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;

import static com.sap.cloud.security.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

public class JwtExpirationValidatorTest {

	private JwtExpirationValidator cut;
	private MockTokenTestFactory tokenFactory;

	@Before
	public void setUp() {
		cut = new JwtExpirationValidator(() -> NOW, CLOCK_SKEW_LEEWAY);
		tokenFactory = new MockTokenTestFactory();
	}

	@Test
	public void token_LacksExpiration_isValid() {
		Token token = tokenFactory.withExpiration(null).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenExpired_beforeClockSkewLeeway_isNotValidAndContainsErrorDescriptionWithDates() {
		Instant expiration = NOW.minus(CLOCK_SKEW_LEEWAY);
		Token token = tokenFactory.withExpiration(expiration).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String description = validationResult.getErrors().get(0).getDescription();
		assertThat(description).contains(NOW.toString()).contains(expiration.toString());
	}

	@Test
	public void tokenExpires_afterClockSkewLeeway_isValid() {
		Token token = tokenFactory.withExpiration(NOW.plus(CLOCK_SKEW_LEEWAY)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenExpired_butStillInClockSkewLeeway_isValid() {
		tokenFactory = new MockTokenTestFactory();
		Token token = tokenFactory.withExpiration(NOW.minus(CLOCK_SKEW_LEEWAY).plus(ONE_SECOND)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

}