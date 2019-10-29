package com.sap.cloud.security.token.validation;

import java.util.ArrayList;

public class ValidationResults {

	public static ValidationResult createInvalid(String errorMessage) {
		ArrayList<ValidationError> validationErrors = new ArrayList<>();
		validationErrors.add(new DefaultValidationError(errorMessage));
		DefaultValidationResult validationResult = new DefaultValidationResult(validationErrors);
		return validationResult;
	}

	public static ValidationResult createValid() {
		return new DefaultValidationResult(new ArrayList<>());
	}

}
