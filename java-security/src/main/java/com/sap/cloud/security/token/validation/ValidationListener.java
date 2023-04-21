/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

/**
 * Implement this interface to register custom validation listener to the
 * {@link CombiningValidator}. Those classes will be called whenever a token is
 * being validated. <br>
 *
 * This might be relevant for writing Audit logs.
 */
public interface ValidationListener {

	void onValidationError(ValidationResult result);

	void onValidationSuccess();

}
