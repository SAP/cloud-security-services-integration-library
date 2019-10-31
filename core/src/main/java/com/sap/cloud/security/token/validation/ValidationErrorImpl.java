package com.sap.cloud.security.token.validation;

public class ValidationErrorImpl implements ValidationError {

	private final String errorMessage;

	public ValidationErrorImpl(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	@Override public String getMessage() {
		return errorMessage;
	}
}
