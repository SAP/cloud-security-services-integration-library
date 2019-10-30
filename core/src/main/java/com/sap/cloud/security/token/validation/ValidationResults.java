package com.sap.cloud.security.token.validation;

import java.util.ArrayList;

public class ValidationResults {

	public static ValidationResult createInvalid(String errorMessage) {
		ArrayList<ValidationError> validationErrors = new ArrayList<>();
		validationErrors.add(new ValidationErrorImpl(errorMessage));
		ValidationResultImpl validationResult = new ValidationResultImpl(validationErrors);
		return validationResult;
	}

	public static ValidationResult createValid() {
		return new ValidationResultImpl(new ArrayList<>());
	}

}
