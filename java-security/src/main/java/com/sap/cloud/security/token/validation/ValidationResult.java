/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import javax.annotation.Nullable;

/**
 * Captures the result of a validation. Normally created by validators that implement the {@link Validator} interface.
 */
public interface ValidationResult {

	/**
	 * Returns true if there is no validation error, false otherwise.
	 *
	 * @return true if there is no validation error.
	 */
	default boolean isValid() {
		return getErrorDescription() == null;
	}

	/**
	 * Returns true if there is a validation error, false otherwise.
	 *
	 * @return true if there is a validation error.
	 */
	default boolean isErroneous() {
		return !isValid();
	}

	/**
	 * Returns true if there is a validation error which might be resolved by retrying the validation.
	 *
	 * @return true if there is a retryable validation error.
	 */
	default boolean isRetryable() {
		return false;
	}

	/**
	 * The validation error that have been found.
	 *
	 * @return the error description or null in case the validation was valid.
	 */
	@Nullable
	String getErrorDescription();
}