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
		assertThat(error.getDescription()).isEqualTo(errorMessage);
	}

	@Test
	public void createValid() {
		ValidationResult validationResult = ValidationResults.createValid();

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void createInvalidWithTemplateString() {
		String errorMessageTemplate = "An error message {} {} {}";
		String[] args = { "first", "second", "third" };
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessageTemplate, args[0], args[1],
				args[2]);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String description = validationResult.getErrors().get(0).getDescription();
		assertThat(description).isEqualTo("An error message first second third");
	}

	@Test
	public void createInvalidWithTemplateString_tooManyPlaceholders_areIgnored() {
		String errorMessageTemplate = "An error message {} {} {}";
		String onlyOne = "first";
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessageTemplate, onlyOne);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String description = validationResult.getErrors().get(0).getDescription();
		assertThat(description).isEqualTo("An error message first {} {}");
	}

	@Test
	public void createInvalidWithTemplateString_tooManyArguments_areIgnored() {
		String errorMessageTemplate = "An error message {}";
		String[] args = { "first", "second", "third" };
		ValidationResult validationResult = ValidationResults.createInvalid(errorMessageTemplate, args);

		assertThat(validationResult.isValid()).isFalse();
		assertThat(validationResult.getErrors()).hasSize(1);
		String description = validationResult.getErrors().get(0).getDescription();
		assertThat(description).isEqualTo("An error message first");
	}

}