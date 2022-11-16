/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

/**
 * Thrown to signal issues during a http client initialization.
 */
public class HttpClientException extends RuntimeException {
	/**
	 * Instantiates a new Service client exception.
	 *
	 * @param message
	 *            the message
	 */
	public HttpClientException(String message) {
		super(message);
	}
}
