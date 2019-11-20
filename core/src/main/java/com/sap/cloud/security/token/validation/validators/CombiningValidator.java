package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;

import java.util.List;

/**
 * This is a special validator that combines several validators into one.
 * By default the validation stops after one invalid result has been found.
 * @param <T>
 *            the type to be validated.
 */
public class CombiningValidator<T> implements Validator<T> {

	private final List<Validator<T>> validators;

	public CombiningValidator(List<Validator<T>> validators) {
		this.validators = validators;
	}

	@Override
	public ValidationResult validate(T t) {
		for (Validator<T> validator : validators) {
			ValidationResult result = validator.validate(t);
			if (result.isErroneous()) {
				return result;
			}
		}
		return ValidationResults.createValid();
	}

	@Override
	public String toString() {
		StringBuilder validatorNames = new StringBuilder();
		for (Validator<T> v : validators) {
			validatorNames.append(v.getClass().getName()).append(',');
		}
		return validatorNames.toString();
	}

}
