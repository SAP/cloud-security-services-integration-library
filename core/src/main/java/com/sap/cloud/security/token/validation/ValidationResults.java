package com.sap.cloud.security.token.validation;

import java.util.ArrayList;

/**
 * This is a factory class to easily create {@link ValidationResult} objects.
 */
public class ValidationResults {

	/**
	 * Creates an invalid {@link ValidationResult} that contains one
	 * {@link ValidationError} with given description.
	 * 
	 * @param errorDescription
	 *            the description used to create the {@link ValidationError}.
	 * @return an invalid {@link ValidationResult} containing one
	 *         {@link ValidationError} with the given error description.
	 */
	public static ValidationResult createInvalid(String errorDescription) {
		ArrayList<ValidationError> validationErrors = new ArrayList<>();
		validationErrors.add(new ValidationErrorImpl(errorDescription));
		ValidationResultImpl validationResult = new ValidationResultImpl(validationErrors);
		return validationResult;
	}

	/**
	 * Creates a valid {@link ValidationResult}, which is a {@link ValidationResult}
	 * that contains no errors.
	 * 
	 * @return a valid validation result.
	 */
	public static ValidationResult createValid() {
		return new ValidationResultImpl(new ArrayList<>());
	}

}
