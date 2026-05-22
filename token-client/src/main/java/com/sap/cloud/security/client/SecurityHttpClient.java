/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import java.io.IOException;

/**
 * Abstraction for HTTP client operations to support different HTTP client implementations.
 * This allows the library to work with both Java 11's HttpClient and Apache HttpClient
 * without creating a direct dependency on either implementation in the core modules.
 */
public interface SecurityHttpClient extends AutoCloseable {

	/**
	 * Execute an HTTP request and return the response.
	 *
	 * @param request the HTTP request to execute
	 * @return the HTTP response
	 * @throws IOException if an I/O error occurs
	 */
	SecurityHttpResponse execute(SecurityHttpRequest request) throws IOException;

	/**
	 * Closes this client and releases any resources associated with it.
	 *
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	void close() throws IOException;
}
