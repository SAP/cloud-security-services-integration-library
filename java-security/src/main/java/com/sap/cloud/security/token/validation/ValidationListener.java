package com.sap.cloud.security.token.validation;

/**
 * Implement this interface to register custom validation listener to the
 * {@link CombiningValidator}. Those classes will be called whenever a token is
 * being validated. <br>
 *
 * This might be relevant for writing Audit logs.
 */
public interface ValidationListener {

	void onValidationError(ValidationResult result);

	void onValidationSuccess();

}
