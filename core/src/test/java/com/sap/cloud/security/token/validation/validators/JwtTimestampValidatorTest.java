package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.MockTokenBuilder;
import com.sap.cloud.security.token.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.time.Instant;

import static com.sap.cloud.security.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

public class JwtTimestampValidatorTest {

	private JwtTimestampValidator cut;
	private MockTokenBuilder tokenFactory;

	@Before
	public void setUp() {
		cut = new JwtTimestampValidator(() -> NOW, ONE_MINUTE);
		tokenFactory = new MockTokenBuilder();
	}

	@Test
	public void token_LacksExpiration_isValid() {
		Token token = tokenFactory.withExpiration(null).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenExpired_beforeClockSkewLeeway_isNotValidAndContainsErrorDescriptionWithDates() {
		Instant expiration = NOW.minus(ONE_MINUTE);
		Token token = tokenFactory.withExpiration(expiration).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String description = validationResult.getErrors().get(0).getDescription();
		assertThat(description).contains(NOW.toString()).contains(expiration.toString());
	}

	@Test
	public void tokenExpires_afterClockSkewLeeway_isValid() {
		Token token = tokenFactory.withExpiration(NOW.plus(ONE_MINUTE)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenExpired_butStillInClockSkewLeeway_isValid() {
		Token token = tokenFactory.withExpiration(NOW.minus(ONE_MINUTE).plus(ONE_SECOND)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenLacksNotBefore_isValid() {
		Token token = tokenFactory.withNotBefore(null).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenNotBefore_now_isValid() {
		Token token = tokenFactory.withNotBefore(NOW).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenNotBefore_insideClockSkewLeeway_isValid() {
		Token token = tokenFactory.withNotBefore(NOW.plus(ONE_MINUTE).minus(ONE_SECOND)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenNotBefore_afterClockSkewLeeway_isNotValidAndContainsErrorDescription() {
		Instant inOneMinute = NOW.plus(ONE_MINUTE);
		Token token = tokenFactory.withNotBefore(inOneMinute).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String errorDescription = validationResult.getErrors().get(0).getDescription();
		assertThat(errorDescription).contains(NOW.toString()).contains(inOneMinute.toString());
	}

	@Test
	public void tokenNotBeforeIsValidButIsAlreadyExpired_isNotValid() {
		Token token = tokenFactory
				.withExpiration(NOW.minus(Duration.ofMinutes(2)))
				.withNotBefore(NOW)
				.build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
	}

	@Test
	public void tokenNotExpiredButNotBeforeNotReachedYet_isNotValid() {
		Instant inTwoMinutes = NOW.plus(Duration.ofMinutes(2));
		Token token = tokenFactory
				.withExpiration(inTwoMinutes)
				.withNotBefore(inTwoMinutes)
				.build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
	}


}