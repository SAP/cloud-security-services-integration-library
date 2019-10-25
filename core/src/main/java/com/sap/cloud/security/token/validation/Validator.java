package com.sap.cloud.security.token.validation;

public interface Validator<T> {

	ValidationResult validate(T t);
}
