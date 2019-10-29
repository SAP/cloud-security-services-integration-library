package com.sap.cloud.security.token.validation;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ValidationResultsTest {

	@Test
	public void createInvalid() {
		String errorMessage = "An error message";
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessage);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).size().isOne();
		ValidationError error = validationResult.getErrors().get(0);
		assertThat(error.getMessage()).isEqualTo(errorMessage);
	}

	@Test
	public void createValid() {
		ValidationResult validationResult = ValidationResults.createValid();

		assertThat(validationResult.isValid()).isTrue();
	}

}