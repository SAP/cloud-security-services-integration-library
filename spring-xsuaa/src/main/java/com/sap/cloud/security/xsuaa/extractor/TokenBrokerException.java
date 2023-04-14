/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

public class TokenBrokerException extends Exception {

	private static final long serialVersionUID = 1L;

	public TokenBrokerException(String message, Exception e) {
		super(message, e);
	}

	public TokenBrokerException(String message) {
		super(message);
	}

}