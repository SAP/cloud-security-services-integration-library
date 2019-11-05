package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import org.junit.Before;
import org.junit.Test;

import java.time.Instant;

import static com.sap.cloud.security.TestConstants.*;
import static org.assertj.core.api.Assertions.assertThat;

public class JwtNotBeforeValidatorTest {

	private JwtNotBeforeValidator cut;
	private MockTokenTestFactory tokenFactory;

	@Before
	public void setUp() {
		cut = new JwtNotBeforeValidator(() -> NOW, CLOCK_SKEW_LEEWAY);
		tokenFactory = new MockTokenTestFactory();
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
		Token token = tokenFactory.withNotBefore(NOW.plus(CLOCK_SKEW_LEEWAY).minus(ONE_SECOND)).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void tokenNotBefore_afterClockSkewLeeway_isNotValidAndContainsErrorDescription() {
		Instant inOneMinute = NOW.plus(CLOCK_SKEW_LEEWAY);
		Token token = tokenFactory.withNotBefore(inOneMinute).build();

		ValidationResult validationResult = cut.validate(token);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String errorDescription = validationResult.getErrors().get(0).getDescription();
		assertThat(errorDescription).contains(NOW.toString()).contains(inOneMinute.toString());
	}


}