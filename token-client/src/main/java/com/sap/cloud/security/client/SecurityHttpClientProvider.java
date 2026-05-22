/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Comparator;
import java.util.ServiceLoader;
import java.util.stream.StreamSupport;

/**
 * Provides access to {@link SecurityHttpClient} instances using the ServiceLoader mechanism.
 * This class discovers all available {@link SecurityHttpClientFactory} implementations
 * and uses the one with the highest priority.
 */
public class SecurityHttpClientProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecurityHttpClientProvider.class);
	private static volatile SecurityHttpClientFactory factory;

	private SecurityHttpClientProvider() {
		// utility class
	}

	/**
	 * Creates a new SecurityHttpClient using the discovered factory with highest priority.
	 *
	 * @param clientIdentity the client identity for mTLS connections, or null for non-mTLS
	 * @return a new SecurityHttpClient instance
	 * @throws HttpClientException if no factory is available or client creation fails
	 */
	public static SecurityHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		return getFactory().createClient(clientIdentity);
	}

	/**
	 * Gets the factory with the highest priority from ServiceLoader.
	 *
	 * @return the factory to use
	 * @throws HttpClientException if no factory is available
	 */
	private static SecurityHttpClientFactory getFactory() throws HttpClientException {
		if (factory == null) {
			synchronized (SecurityHttpClientProvider.class) {
				if (factory == null) {
					factory = loadFactory();
				}
			}
		}
		return factory;
	}

	private static SecurityHttpClientFactory loadFactory() throws HttpClientException {
		ServiceLoader<SecurityHttpClientFactory> loader = ServiceLoader.load(SecurityHttpClientFactory.class);

		return StreamSupport.stream(loader.spliterator(), false)
				.peek(f -> LOGGER.debug("Found SecurityHttpClientFactory: {} with priority {}",
						f.getClass().getName(), f.getPriority()))
				.max(Comparator.comparingInt(SecurityHttpClientFactory::getPriority))
				.orElseThrow(() -> new HttpClientException(
						"No SecurityHttpClientFactory implementation found. " +
								"Ensure Java 11+ HttpClient is available."));
	}

	/**
	 * Resets the cached factory (mainly for testing purposes).
	 */
	static void reset() {
		factory = null;
	}
}
