package com.sap.cloud.security.token.validation;

import java.util.List;

public class DefaultValidationResult implements ValidationResult {

	private final List<ValidationError> validationErrors;

	public DefaultValidationResult(List<ValidationError> validationErrors) {
		this.validationErrors = validationErrors;
	}

	@Override public List<ValidationError> getErrors() {
		return validationErrors;
	}

}
