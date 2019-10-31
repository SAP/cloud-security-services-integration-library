package com.sap.cloud.security.token.validation;

import java.util.ArrayList;
import java.util.List;

/**
 * This is a special validator that combines several validators into one. To
 * create an instance use the {@link #builder} method. By default the validation
 * stops after one invalid result has been found. To not stop validating use
 * {@link CombiningValidatorBuilder#validateAll}.
 * 
 * @param <T>
 *            the type to be validated.
 */
public class CombiningValidator<T> implements Validator<T> {

	private final List<Validator<T>> validators;
	private final boolean stopAfterFirstInvalidResult;

	private CombiningValidator(List<Validator<T>> validators, boolean stopAfterFirstInvalidResult) {
		this.validators = validators;
		this.stopAfterFirstInvalidResult = stopAfterFirstInvalidResult;
	}

	@Override
	public ValidationResult validate(T t) {
		List<ValidationError> validationErrors = new ArrayList<>();
		for (Validator<T> validator : validators) {
			ValidationResult result = validator.validate(t);
			validationErrors.addAll(result.getErrors());
			if (shouldStop(result)) {
				return new ValidationResultImpl(validationErrors);
			}
		}
		return new ValidationResultImpl(validationErrors);
	}

	private boolean shouldStop(ValidationResult result) {
		return stopAfterFirstInvalidResult && !result.isValid();
	}

	public static <U> CombiningValidatorBuilder<U> builder() {
		return new CombiningValidatorBuilder<>();
	}

	public static class CombiningValidatorBuilder<U> {
		private final List<Validator<U>> validators = new ArrayList<>();
		private boolean stopAfterFirstInvalidResult = true;

		/**
		 * Add the validator to the validation chain.
		 * 
		 * @param validator
		 *            the validator used for validation.
		 * @return this builder.
		 */
		public CombiningValidatorBuilder<U> with(Validator<U> validator) {
			validators.add(validator);
			return this;
		}

		/**
		 * Causes the created validator to not stop validating after the first invalid
		 * result.
		 * 
		 * @return this builder.
		 */
		public CombiningValidatorBuilder<U> validateAll() {
			stopAfterFirstInvalidResult = false;
			return this;
		}

		/**
		 * @return the validator.
		 */
		public CombiningValidator<U> build() {
			return new CombiningValidator<>(validators, stopAfterFirstInvalidResult);
		}
	}

}
