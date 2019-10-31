package com.sap.cloud.security.token.validation;

/**
 * Captures information about specific validation errors. Normally contained
 * inside a by a {@link ValidationResult}.
 */
public interface ValidationError {

	/**
	 * A description of the specific validation error.
	 * 
	 * @return the description.
	 */
	String getDescription();

}
