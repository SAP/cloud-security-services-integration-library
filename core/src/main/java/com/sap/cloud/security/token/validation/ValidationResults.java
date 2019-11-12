package com.sap.cloud.security.token.validation;

import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.MessageFormatter;

/**
 * This is a factory class to easily create {@link ValidationResult} objects.
 */
public class ValidationResults {

	private ValidationResults() {
		// factory
	}

	private static final Logger logger = LoggerFactory.getLogger(ValidationResults.class);

	/**
	 * Creates an invalid {@link ValidationResult} that contains one
	 * {@link ValidationError} with given description.
	 * 
	 * @param errorMesssage
	 *            the error description.
	 * @return an invalid {@link ValidationResult} containing one
	 *         {@link ValidationError} with the given error description.
	 */
	public static ValidationResult createInvalid(String errorMesssage) {
		logger.warn(errorMesssage);
		return new ValidationResultImpl(new ValidationErrorImpl(errorMesssage));
	}

	/**
	 * Works just like {@link #createInvalid(String)} but accepts a template string
	 * with placeholders "{}" that are substituted with the given arguments. Works like
	 * described in {@link MessageFormatter}.
	 *
	 * For example,
	 *
	 * <pre>
	 * MessageFormatter.format(&quot;Hi {}.&quot;, &quot;there&quot;);
	 * </pre>
	 *
	 * will return the string "Hi there.".
	 * <p>
	 * 
	 * @param errorMessageTemplate
	 *            the description as template used to create the
	 *            {@link ValidationError}.
	 * @param arguments
	 *            the arguments that are filled inside the description template.
	 * @return an invalid {@link ValidationResult} containing one
	 *         {@link ValidationError} with the given error description.
	 */
	public static ValidationResult createInvalid(String errorMessageTemplate, Object... arguments) {
		String format = MessageFormatter.arrayFormat(errorMessageTemplate, arguments).getMessage();
		return createInvalid(format);
	}

	static class ValidationResultImpl implements ValidationResult {

		private final ValidationError validationError;

		public ValidationResultImpl(ValidationError validationError) {
			this.validationError = validationError;
		}

		public ValidationResultImpl() {
			this(null);
		}

		@Override public boolean isValid() {
			return getErrorDescription() == null;
		}

		@Override public boolean isErronous() {
			return !isValid();
		}

		@Nullable
		@Override public String getErrorDescription() {
			return validationError != null ? validationError.getDescription() : null;
		}

		@Override public String toString() {
			return isValid() ? "Validation was successful." : getErrorDescription();
		}
	}

	/**
	 * Captures information about specific validation errors. Normally contained
	 * inside a by a {@link ValidationResult}.
	 */
	 interface ValidationError {

		/**
		 * A description of the specific validation error.
		 *
		 * @return the description.
		 */
		String getDescription();

	}

	 private static final ValidationResult VALID_RESULT = new ValidationResultImpl();
	/**
	 * Creates a valid {@link ValidationResult}, which is a {@link ValidationResult}
	 * that contains no errors.
	 *
	 * @return a valid validation result.
	 */
	public static ValidationResult createValid() {
		return VALID_RESULT;
	}

	static class ValidationErrorImpl implements ValidationError {

		private final String errorMessage;

		public ValidationErrorImpl(String errorMessage) {
			this.errorMessage = errorMessage;
		}

		@Override
		public String getDescription() {
			return errorMessage;
		}
	}
}
