package com.sap.cloud.security.token.validation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

/**
 * This is a factory class to easily create {@link ValidationResult} objects.
 */
public class ValidationResults {

	private static final Logger logger = LoggerFactory.getLogger(ValidationResults.class);

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
		logger.warn(errorDescription);
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
		logger.info("Valid validation result created");
		return new ValidationResultImpl(new ArrayList<>());
	}

}
