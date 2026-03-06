/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;

/**
 * @deprecated Use {@link SecurityHttpClientProvider} instead. This interface is kept for backward compatibility
 * in the legacy module. The new abstraction {@link SecurityHttpClient} allows switching between different
 * HTTP client implementations without recompilation.
 */
@Deprecated(since = "4.0.0", forRemoval = true)
public interface HttpClientFactory {

	/**
	 * @deprecated Use {@link SecurityHttpClientProvider#createClient(ClientIdentity)} instead.
	 *
	 * Provides SecurityHttpClient based on ClientIdentity details. For ClientIdentity that is certificate based it
	 * will resolve https client using the provided ClientIdentity, if the ClientIdentity wasn't provided it will return
	 * default HttpClient.
	 *
	 * @param clientIdentity
	 * 		for X.509 certificate based communication {@link ClientCertificate} implementation of ClientIdentity interface
	 * 		should be provided
	 * @return SecurityHttpClient instance
	 * @throws HttpClientException
	 * 		in case HTTPS Client could not be setup
	 */
	@Deprecated(since = "4.0.0", forRemoval = true)
	SecurityHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException;

	/**
	 * @deprecated Use {@link SecurityHttpClientProvider#createClient(ClientIdentity)} instead.
	 *
	 * Don't close the HTTPClient when you've provided it to {@code TokenAuthenticator} or {@code XsuaaTokenFlows}
	 * instance.
	 *
	 * @param clientIdentity
	 * 		to identify the identity provider client.
	 * @return SecurityHttpClient instance
	 * @throws HttpClientException
	 */
	@Deprecated(since = "4.0.0", forRemoval = true)
	static SecurityHttpClient create(ClientIdentity clientIdentity) throws HttpClientException {
		return SecurityHttpClientProvider.createClient(clientIdentity);
	}
}
