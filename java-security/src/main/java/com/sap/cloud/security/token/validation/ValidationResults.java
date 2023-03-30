/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.helpers.MessageFormatter;

import javax.annotation.Nullable;

/**
 * This is a factory class to easily create {@link ValidationResult} objects.
 */
public class ValidationResults {

	private ValidationResults() {
		// factory
	}

	private static final Logger logger = LoggerFactory.getLogger(ValidationResults.class);

	/**
	 * Creates an invalid {@link ValidationResult} that contains an error
	 * description.
	 * 
	 * @param errorDescription
	 *            the error description.
	 * @return an invalid {@link ValidationResult} containing an error description.
	 */
	public static ValidationResult createInvalid(String errorDescription) {
		logger.warn(errorDescription);
		return new ValidationResultImpl(errorDescription);
	}

	/**
	 * Works just like {@link #createInvalid(String)} but accepts a template string
	 * with placeholders "{}" that are substituted with the given arguments. Works
	 * like described in {@link MessageFormatter}.
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
	 * @param errorDescriptionTemplate
	 *            the description as template used to create the error description.
	 * @param arguments
	 *            the arguments that are filled inside the description template.
	 * @return an invalid {@link ValidationResult} containing one error description.
	 */
	public static ValidationResult createInvalid(String errorDescriptionTemplate, Object... arguments) {
		String format = MessageFormatter.arrayFormat(errorDescriptionTemplate, arguments).getMessage();
		return createInvalid(format);
	}

	/**
	 * Creates a valid {@link ValidationResult}, which is a {@link ValidationResult}
	 * that contains no errors.
	 *
	 * @return a valid validation result.
	 */
	public static ValidationResult createValid() {
		return VALID_RESULT;
	}

	static class ValidationResultImpl implements ValidationResult {

		private final String validationError;

		public ValidationResultImpl(String validationError) {
			this.validationError = validationError;
		}

		public ValidationResultImpl() {
			this(null);
		}

		@Nullable
		@Override
		public String getErrorDescription() {
			return validationError;
		}

		@Override
		public String toString() {
			return isValid() ? "Validation was successful." : getErrorDescription();
		}
	}

	private static final ValidationResult VALID_RESULT = new ValidationResultImpl();

}
