/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import org.apache.http.impl.client.CloseableHttpClient;

/**
 * Factory interface for creating Apache {@link CloseableHttpClient} instances.
 *
 * <p><strong>Deprecation Notice - 3-Step Migration Plan:</strong>
 * <ul>
 *   <li><strong>Version 4.x (current):</strong> This interface is deprecated but fully functional with Apache HttpClient 4.
 *       Existing code continues to work without changes.</li>
 *   <li><strong>Version 5.0.0:</strong> This interface will be changed to return {@link SecurityHttpClient} instead of
 *       {@link CloseableHttpClient}. Code using this interface will need to be updated.</li>
 *   <li><strong>Version 6.0.0:</strong> This interface will be removed entirely.</li>
 * </ul>
 *
 * <p><strong>Recommended Migration:</strong> Use {@link SecurityHttpClientProvider#createClient(ClientIdentity)} instead,
 * which returns a {@link SecurityHttpClient} that works with the modern Java 11 HttpClient by default.
 *
 * @deprecated Since 4.0.0. Use {@link SecurityHttpClientProvider} instead.
 *             This interface will change its return type in 5.0.0 and be removed in 6.0.0.
 * @see SecurityHttpClientProvider
 * @see SecurityHttpClient
 */
@Deprecated(since = "4.0.0", forRemoval = true)
public interface HttpClientFactory {

	/**
	 * Creates a {@link CloseableHttpClient} based on the provided ClientIdentity.
	 * For certificate-based ClientIdentity, an HTTPS client with mTLS support is created.
	 *
	 * <p><strong>Deprecation:</strong> This method will return {@link SecurityHttpClient} in version 5.0.0
	 * and will be removed in version 6.0.0.
	 *
	 * @param clientIdentity for X.509 certificate based communication, provide a {@link ClientCertificate}
	 *                       implementation; pass null for a default HTTP client
	 * @return HTTP or HTTPS client configured for the given identity
	 * @throws HttpClientException if the HTTPS client could not be created
	 * @deprecated Since 4.0.0. Use {@link SecurityHttpClientProvider#createClient(ClientIdentity)} instead.
	 */
	@Deprecated(since = "4.0.0", forRemoval = true)
	CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException;

	/**
	 * Creates a {@link CloseableHttpClient} using the default factory implementation.
	 *
	 * <p><strong>Important:</strong> Don't close the returned HttpClient when you've provided it to
	 * {@code TokenAuthenticator} or {@code XsuaaTokenFlows} - they manage its lifecycle.
	 *
	 * <p><strong>Deprecation:</strong> This method will return {@link SecurityHttpClient} in version 5.0.0
	 * and will be removed in version 6.0.0.
	 *
	 * @param clientIdentity the client identity for mTLS connections, or null for non-mTLS
	 * @return HTTP or HTTPS client
	 * @throws HttpClientException if client creation fails
	 * @deprecated Since 4.0.0. Use {@link SecurityHttpClientProvider#createClient(ClientIdentity)} instead.
	 */
	@Deprecated(since = "4.0.0", forRemoval = true)
	static CloseableHttpClient create(ClientIdentity clientIdentity) throws HttpClientException {
		return new DefaultHttpClientFactory().createClient(clientIdentity);
	}
}