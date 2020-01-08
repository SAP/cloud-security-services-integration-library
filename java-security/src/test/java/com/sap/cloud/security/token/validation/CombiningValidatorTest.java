package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.*;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.util.Lists.newArrayList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;

public class CombiningValidatorTest {

	public static final Token TOKEN = null;
	private static final String FIRST_ERROR_MESSAGE = "firstMessage";
	private static final String SECOND_ERROR_MESSAGE = "secondMessage";

	@Test
	public void validate_containsNoValidators_validResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(new ArrayList<>());

		ValidationResult validationResult = combiningValidator.validate(TOKEN);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoValidValidators_validResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				newArrayList(validValidator(), validValidator()));

		ValidationResult validationResult = combiningValidator.validate(TOKEN);

		assertThat(validationResult.isValid()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_invalidResult() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				newArrayList(invalidValidator(), invalidValidator()));

		ValidationResult validationResult = combiningValidator.validate(TOKEN);

		assertThat(validationResult.isErroneous()).isTrue();
	}

	@Test
	public void validate_twoInvalidValidators_containsOnlyOneErrorMessages() {
		Validator<Token> combiningValidator = new CombiningValidator<>(
				newArrayList(validValidator(), invalidValidator(FIRST_ERROR_MESSAGE),
						invalidValidator(SECOND_ERROR_MESSAGE)));

		String error = combiningValidator.validate(TOKEN).getErrorDescription();

		assertThat(error).isEqualTo(FIRST_ERROR_MESSAGE);
	}

	@Test
	public void registerValidationListener_validValidator_callsOnValidationSuccess() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(newArrayList(validValidator()));
		ValidationListener validationListenerMock = Mockito.mock(ValidationListener.class);
		combiningValidator.registerValidationListener(validationListenerMock);

		combiningValidator.validate(TOKEN);

		Mockito.verify(validationListenerMock, times(1)).onValidationSuccess();
		Mockito.verifyNoMoreInteractions(validationListenerMock);
	}

	@Test
	public void registerValidationListener_invalidValidator_callsOnValidationSuccess() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(newArrayList(invalidValidator()));
		ValidationListener validationListenerMock = Mockito.mock(ValidationListener.class);
		combiningValidator.registerValidationListener(validationListenerMock);

		combiningValidator.validate(TOKEN);

		Mockito.verify(validationListenerMock, times(1)).onValidationError(any(ValidationResult.class));
		Mockito.verifyNoMoreInteractions(validationListenerMock);
	}

	@Test
	public void registerValidationListener_listenerIsRemoved_isNotCalled() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(newArrayList(validValidator()));
		ValidationListener validationListenerMock = Mockito.mock(ValidationListener.class);
		combiningValidator.registerValidationListener(validationListenerMock);
		combiningValidator.removeValidationListener(validationListenerMock);

		combiningValidator.validate(TOKEN);

		Mockito.verifyZeroInteractions(validationListenerMock);
	}

	@Test
	public void toString_containsValidatorName() {
		CombiningValidator<Token> combiningValidator = new CombiningValidator<>(
				newArrayList(new MyTokenValidator()));

		assertThat(combiningValidator.toString()).contains(MyTokenValidator.class.getSimpleName());
	}

	private class MyTokenValidator implements Validator<Token> {
		@Override
		public ValidationResult validate(Token token) {
			return ValidationResults.createValid();
		}

	}

	private Validator<Token> validValidator() {
		return (obj) -> ValidationResults.createValid();
	}

	private Validator<Token> invalidValidator() {
		return invalidValidator(FIRST_ERROR_MESSAGE);
	}

	private Validator<Token> invalidValidator(String errorMessage) {
		return (obj) -> ValidationResults.createInvalid(errorMessage);
	}

}