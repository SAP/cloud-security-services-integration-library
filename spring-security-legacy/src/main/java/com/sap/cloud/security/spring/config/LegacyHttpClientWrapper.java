/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.spring.config;

import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.apache.ApacheHttpClientAdapter;
import org.apache.http.impl.client.CloseableHttpClient;

/**
 * Utility class for backward compatibility with Apache HttpClient in the legacy module.
 * Provides methods to wrap Apache's CloseableHttpClient as SecurityHttpClient.
 */
public class LegacyHttpClientWrapper {

	private LegacyHttpClientWrapper() {
		// utility class
	}

	/**
	 * Wraps an Apache CloseableHttpClient (HTTP Client 4.x) as a SecurityHttpClient.
	 * This allows users who have customized their CloseableHttpClient configuration
	 * to continue using it with the new SecurityHttpClient abstraction.
	 *
	 * <p>Example usage:
	 * <pre>{@code
	 * CloseableHttpClient customHttpClient = // ... your custom configuration
	 * SecurityHttpClient securityHttpClient = LegacyHttpClientWrapper.wrap(customHttpClient);
	 * OAuth2TokenService tokenService = new DefaultOAuth2TokenService(securityHttpClient);
	 * }</pre>
	 *
	 * @param apacheHttpClient the Apache CloseableHttpClient to wrap
	 * @return a SecurityHttpClient that delegates to the provided Apache client
	 */
	public static SecurityHttpClient wrap(CloseableHttpClient apacheHttpClient) {
		if (apacheHttpClient == null) {
			throw new IllegalArgumentException("Apache HttpClient must not be null");
		}
		return new ApacheHttpClientAdapter(apacheHttpClient);
	}
}
