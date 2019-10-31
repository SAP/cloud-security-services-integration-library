package com.sap.cloud.security.token.validation;

import java.util.List;

/**
 * Captures the result of a validation. Normally created by validators that
 * implement the {@link Validator} interface.
 */
public interface ValidationResult {

	/**
	 * Returns true if there are no validation errors, false otherwise.
	 * 
	 * @return true if there are no validation errors.
	 */
	default boolean isValid() {
		return getErrors().isEmpty();
	}

	/**
	 * The list of validation errors that have been found.
	 * 
	 * @return the errors.
	 */
	List<ValidationError> getErrors();
}