/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.xsa.security.container;

/**
 * deprecated with version 2.4.0 in favor of the new SAP Java Client library.
 */
public class XSUserInfoException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public XSUserInfoException(String message) {
		super(message);
	}

	public XSUserInfoException(String message, Throwable reason) {
		super(message, reason);
	}

}
