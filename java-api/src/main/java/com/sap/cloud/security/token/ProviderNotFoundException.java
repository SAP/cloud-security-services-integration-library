/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

/**
 * A dedicated runtime exception for missing implementations in
 * {@link java.util.ServiceLoader} context
 */
public class ProviderNotFoundException extends RuntimeException {

	public ProviderNotFoundException() {
		super();
	}

	public ProviderNotFoundException(String message) {
		super(message);
	}
}
