package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.validation.ValidationResult;

/**
 * Implement this interface to register custom validation listener to the
 * {@link CombiningValidator}. Those classes will be called whenever a token is
 * being validated.
 */
public interface ValidationListener {

	void onValidationError(ValidationResult result);

	void onValidationSuccess();

}
