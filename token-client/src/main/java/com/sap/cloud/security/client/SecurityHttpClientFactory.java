/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;

/**
 * Factory interface for creating {@link SecurityHttpClient} instances.
 * Implementations of this interface can be discovered using the ServiceLoader mechanism.
 * The factory with the highest priority will be used.
 */
public interface SecurityHttpClientFactory {

	/**
	 * Creates a new HTTP client instance.
	 *
	 * @param clientIdentity the client identity for mTLS connections, or null for non-mTLS
	 * @return a new SecurityHttpClient instance
	 * @throws HttpClientException if the client cannot be created
	 */
	SecurityHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException;

	/**
	 * Returns the priority of this factory. Higher values indicate higher priority.
	 * The default Java 11 HttpClient implementation should return 0.
	 * Third-party implementations (like Apache HttpClient) should return higher values.
	 *
	 * @return the priority (default implementations should return 0)
	 */
	default int getPriority() {
		return 0;
	}
}
