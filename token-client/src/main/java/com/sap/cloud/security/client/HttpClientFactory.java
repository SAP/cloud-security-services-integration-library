/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

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

	Logger LOGGER = LoggerFactory.getLogger(HttpClientFactory.class);

	String DEFAULT_HTTP_CLIENT_FACTORY = "com.sap.cloud.security.client.DefaultHttpClientFactory";

	/**
	 * @deprecated Since 4.0.0. Use {@link SecurityHttpClientFactory} with {@link SecurityHttpClientProvider} instead.
	 *             This field will be removed in version 6.0.0.
	 */
	@Deprecated(since = "4.0.0", forRemoval = true)
	@SuppressWarnings("unchecked")
	List<HttpClientFactory> services = new ArrayList() {
		{
			ServiceLoader.load(HttpClientFactory.class).forEach(this::add);
			LOGGER.info("loaded HttpClientFactory service providers: {}", this);
		}
	};

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
	 * Creates a {@link CloseableHttpClient} using the discovered factory implementation.
	 * If a custom {@link HttpClientFactory} is registered via {@code META-INF/services},
	 * it will be used (with a deprecation warning). Otherwise, the {@link DefaultHttpClientFactory} is used.
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
		if (services.isEmpty()) {
			throw new HttpClientException(
					"No HttpClientFactory service could be found in the classpath. "
							+ "Ensure that token-client or token-client-apache is on the classpath.");
		}
		if (services.size() > 2) {
			throw new HttpClientException(
					"More than 1 custom HttpClientFactory service provider found. There should be only one.");
		}
		if (services.size() == 2) {
			HttpClientFactory customFactory = services.stream()
					.filter(f -> !f.getClass().getName().equals(DEFAULT_HTTP_CLIENT_FACTORY))
					.findFirst()
					.orElse(services.get(0));
			LOGGER.warn("Using deprecated custom HttpClientFactory '{}'. "
					+ "Migrate to SecurityHttpClientFactory with SecurityHttpClientProvider.",
					customFactory.getClass().getName());
			return customFactory.createClient(clientIdentity);
		}
		return services.get(0).createClient(clientIdentity);
	}
}