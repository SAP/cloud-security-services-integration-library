package com.sap.cloud.security.token.validation;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CombiningValidator<T> implements Validator<T> {

	private final Set<Validator<T>> validators;

	private CombiningValidator(Set<Validator<T>> validators) {
		this.validators = validators;
	}

	@Override
	public ValidationResult validate(T t) {
		List<ValidationError> validationErrors = validators.stream()
				.map(v -> v.validate(t))
				.flatMap(result -> result.getErrors().stream())
				.collect(Collectors.toList());
		return new ValidationResultImpl(validationErrors);
	}

	public static <U> CombiningValidatorBuilder<U> builder() {
		return new CombiningValidatorBuilder<>();
	}

	public static class CombiningValidatorBuilder<U> {
		private final Set<Validator<U>> validators = new HashSet<>();

		public CombiningValidatorBuilder<U> with(Validator<U> validator) {
			validators.add(validator);
			return this;
		}

		public CombiningValidator<U> build() {
			return new CombiningValidator<>(validators);
		}
	}

}
