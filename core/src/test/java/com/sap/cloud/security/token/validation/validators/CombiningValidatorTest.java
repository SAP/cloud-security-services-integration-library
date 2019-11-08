package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

public class CombiningValidatorTest {

	private static final String FIRST_ERROR_MESSAGE = "firstMessage";
	private static final String SECOND_ERROR_MESSAGE = "secondMessage";

	@Test
	public void validate_containsNoValidators_validResult() {
		Validator<Object> combiningValidator = CombiningValidator.builderFor().build();

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoValidValidators_validResult() {
		Validator<Object> combiningValidator = CombiningValidator.builderFor()
				.with(validValidator())
				.with(validValidator())
				.build();

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_invalidResult() {
		Validator<Object> combiningValidator = CombiningValidator.builderFor()
				.with(invalidValidator())
				.with(invalidValidator())
				.build();

		ValidationResult validationResult = combiningValidator.validate(null);

		assertThat(validationResult.isValid()).isFalse();
	}

	@Test
	public void validate_twoInvalidValidators_containsOnlyOneErrorMessages() {
		Validator<Object> combiningValidator = CombiningValidator.builderFor()
				.with(validValidator())
				.with(invalidValidator(FIRST_ERROR_MESSAGE))
				.with(invalidValidator(SECOND_ERROR_MESSAGE)).build();

		String error = combiningValidator.validate(null).getErrorDescription();

		assertThat(error).isEqualTo(FIRST_ERROR_MESSAGE);
	}

	@Test
	public void validate_twoInvalidValidatorsWithValidateAll_containsBothErrorMessages() {
		CombiningValidator<Object> combiningValidator = CombiningValidator.builderFor()
				.with(validValidator())
				.with(invalidValidator(FIRST_ERROR_MESSAGE))
				.with(invalidValidator(SECOND_ERROR_MESSAGE))
				.with(validValidator())
				.validateAll()
				.build();

		ValidationResult result = combiningValidator.validate(null);
		assertThat(result.getErrorDescription()).isEqualTo("2 out of 4 validators reported an error. Please see detailed error descriptions.");
		assertThat(result.isValid()).isEqualTo(false);

		List<String> errorMessages = combiningValidator.getAllErrorDescriptions();
		assertThat(errorMessages).containsExactly(FIRST_ERROR_MESSAGE, SECOND_ERROR_MESSAGE);
	}

	private Validator<Object> validValidator() {
		return (obj) -> ValidationResults.createValid();
	}

	private Validator<Object> invalidValidator() {
		return invalidValidator(FIRST_ERROR_MESSAGE);
	}

	private Validator<Object> invalidValidator(String errorMessage) {
		return (obj) -> ValidationResults.createInvalid(errorMessage);
	}

}