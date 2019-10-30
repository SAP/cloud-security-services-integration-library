package com.sap.cloud.security.token.validation;

import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

public class CombiningValidatorTest {

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
	public void validate_twoValidValidators_containsErrorMessages() {
		String firstErrorMessage = "firstMessage";
		String secondErrorMessage = "secondMessage";
		Validator<Object> combinigValidator = CombiningValidator.builder()
				.with(invalidValidator(firstErrorMessage))
				.with(invalidValidator(secondErrorMessage))
				.build();

		List<ValidationError> errors = getValidationErrors(combinigValidator);

		assertThat(errors).size().isEqualTo(2);
		List<String> errorMessages = errors.stream().map(ValidationError::getMessage).collect(Collectors.toList());
		assertThat(errorMessages).containsExactlyInAnyOrder(firstErrorMessage, secondErrorMessage);
	}

	@Test
	public void validate_twoValidValidatorsWhichAreTheSameObject_onlyOneIsUsed() {
		Validator<Object> invalidValidator = invalidValidator();
		Validator<Object> combinigValidator = CombiningValidator.builder()
				.with(invalidValidator)
				.with(invalidValidator)
				.build();

		List<ValidationError> errors = getValidationErrors(combinigValidator);

		assertThat(errors).size().isEqualTo(1);
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
		return invalidValidator("the error message");
	}
}