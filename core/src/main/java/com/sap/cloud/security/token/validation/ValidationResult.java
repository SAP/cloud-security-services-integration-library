package com.sap.cloud.security.token.validation;

import java.util.List;

public interface ValidationResult {

	default boolean isValid() {
		return getErrors().isEmpty();
	}

	List<ValidationError> getErrors();
}