/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.token.Token;

public final class TokenTestValidator implements Validator<Token> {

	public static final String DEFAULT_ERROR_DESCRIPTION = "test error description";

	private ValidationResult validationResult;

	private TokenTestValidator(ValidationResult validationResult) {
		this.validationResult = validationResult;
	}

	public static TokenTestValidator createValid() {
		return new TokenTestValidator(ValidationResults.createValid());
	}

	public static TokenTestValidator createInvalid() {
		return TokenTestValidator.createInvalid(DEFAULT_ERROR_DESCRIPTION);
	}

	public static TokenTestValidator createInvalid(String errorDescription) {
		return new TokenTestValidator(ValidationResults.createInvalid(errorDescription));
	}

	@Override
	public ValidationResult validate(Token token) {
		return validationResult;
	}

}
