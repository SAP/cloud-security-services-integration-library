/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

/**
 * Generic validator interface over type {@link T}.
 *
 * @param <T>
 *            the type of the object to be validated.
 */
public interface Validator<T> {

	/**
	 * Validates the given object.
	 *
	 * @param t
	 *            the object of type {@link T} to be validated.
	 * @return the validation result as {@link ValidationResult}.
	 */
	ValidationResult validate(T t);
}
