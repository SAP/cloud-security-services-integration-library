/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import java.io.IOException;

/**
 * Exception thrown to signal issues during a token flow execution.
 */
public class TokenFlowException extends IOException {
	private static final long serialVersionUID = 1452898292676860358L;

	/**
	 * Creates a new exception instances.
	 */
	public TokenFlowException() {
		super();
	}

	/**
	 * Creates a new exception instances.
	 *
	 * @param message
	 *            - the error message.
	 * @param cause
	 *            - the error cause.
	 */
	public TokenFlowException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Creates a new exception instances.
	 * 
	 * @param message
	 *            - the error message.
	 */
	public TokenFlowException(String message) {
		super(message);
	}

	/**
	 * Creates a new exception instances.
	 * 
	 * @param cause
	 *            - the error cause.
	 */
	public TokenFlowException(Throwable cause) {
		super(cause);
	}
}
