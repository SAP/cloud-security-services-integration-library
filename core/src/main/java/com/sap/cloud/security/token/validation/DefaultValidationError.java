package com.sap.cloud.security.token.validation;

public class DefaultValidationError implements ValidationError {

	private final String errorMessage;

	public DefaultValidationError(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	@Override public String getMessage() {
		return errorMessage;
	}
}
