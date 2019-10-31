package com.sap.cloud.security.token.validation;

import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

public class CombiningValidatorTest {

	private static final String FIRST_ERROR_MESSAGE = "firstMessage";
	private static final String SECOND_ERROR_MESSAGE = "secondMessage";

	@Test
	public void validate_containsNoValidators_validResult() {
		Validator<Object> combinigValidator = CombiningValidator.builder().build();

		ValidationResult validationResult = getValidationResult(combinigValidator);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoValidValidators_validResult() {
		Validator<Object> combinigValidator = CombiningValidator.builder()
				.with(validValidator())
				.with(validValidator())
				.build();

		ValidationResult validationResult = getValidationResult(combinigValidator);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoValidValidators_invalidResult() {
		Validator<Object> combinigValidator = CombiningValidator.builder()
				.with(invalidValidator())
				.with(invalidValidator())
				.build();

		ValidationResult validationResult = getValidationResult(combinigValidator);

		assertThat(validationResult.isValid()).isFalse();
	}

	@Test
	public void validate_twoValidValidators_containsOnlyOneErrorMessages() {
		Validator<Object> combinigValidator = CombiningValidator.builder()
				.with(invalidValidator(FIRST_ERROR_MESSAGE))
				.with(invalidValidator(SECOND_ERROR_MESSAGE)).build();

		List<ValidationError> errors = getValidationErrors(combinigValidator);

		assertThat(errors).size().isEqualTo(1);
		List<String> errorMessages = errors.stream().map(ValidationError::getMessage).collect(Collectors.toList());
		assertThat(errorMessages).containsExactly(FIRST_ERROR_MESSAGE);
	}

	@Test
	public void validate_twoValidValidatorsWithValidateAll_containsBothErrorMessages() {
		Validator<Object> combinigValidator = CombiningValidator.builder()
				.with(invalidValidator(FIRST_ERROR_MESSAGE))
				.with(invalidValidator(SECOND_ERROR_MESSAGE))
				.validateAll()
				.build();

		List<ValidationError> errors = getValidationErrors(combinigValidator);

		assertThat(errors).size().isEqualTo(2);
		List<String> errorMessages = errors.stream().map(ValidationError::getMessage).collect(Collectors.toList());
		assertThat(errorMessages).containsExactly(FIRST_ERROR_MESSAGE, SECOND_ERROR_MESSAGE);
	}

	private ValidationResult getValidationResult(Validator<Object> combinigValidator) {
		return combinigValidator.validate(null);
	}

	private List<ValidationError> getValidationErrors(Validator<Object> combinigValidator) {
		return combinigValidator.validate(null).getErrors();
	}

	private Validator<Object> validValidator() {
		return (obj) -> ValidationResults.createValid();
	}

	private Validator<Object> invalidValidator(String errorMessage) {
		return (obj) -> ValidationResults.createInvalid(errorMessage);
	}

	private Validator<Object> invalidValidator() {
		return invalidValidator(FIRST_ERROR_MESSAGE);
	}
}