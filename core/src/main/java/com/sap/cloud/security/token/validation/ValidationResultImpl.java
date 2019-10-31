package com.sap.cloud.security.token.validation;

import java.util.List;

public class ValidationResultImpl implements ValidationResult {

	private final List<ValidationError> validationErrors;

	public ValidationResultImpl(List<ValidationError> validationErrors) {
		this.validationErrors = validationErrors;
	}

	@Override public List<ValidationError> getErrors() {
		return validationErrors;
	}

}
