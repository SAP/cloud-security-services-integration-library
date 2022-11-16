/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.token.ProviderNotFoundException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.LoggerFactory;

import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Represents a {@link CloseableHttpClient} creation interface.
 */
public interface HttpClientFactory {

	@SuppressWarnings("unchecked")
	List<HttpClientFactory> services = new ArrayList() {
		{
			ServiceLoader.load(HttpClientFactory.class).forEach(this::add);
			LoggerFactory.getLogger(HttpClientFactory.class).info("loaded HttpClientFactory service providers: {}",
					this);
		}
	};

	String DEFAULT_HTTP_CLIENT_FACTORY = "com.sap.cloud.security.client.DefaultHttpClientFactory";

	/**
	 * Provides CloseableHttpClient based on ClientIdentity details. For
	 * ClientIdentity that is certificate based it will resolve https client using
	 * the provided ClientIdentity, if the ClientIdentity wasn't provided it will
	 * return default HttpClient.
	 *
	 * @param clientIdentity
	 *            for X.509 certificate based communication
	 *            {@link ClientCertificate} implementation of ClientIdentity
	 *            interface should be provided
	 * @return HTTP or HTTPS client
	 * @throws HttpClientException
	 *             in case HTTPS Client could not be setup
	 */
	CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException;

	/**
	 * Don't close the HTTPClient when you've provided it to
	 * {@code TokenAuthenticator} or {@code XsuaaTokenFlows} instance.
	 *
	 * @param clientIdentity
	 *            to identify the identity provider client.
	 * @return HTTP or HTTPS client
	 * @throws HttpClientException
	 */
	static CloseableHttpClient create(ClientIdentity clientIdentity) throws HttpClientException {
		if (services.isEmpty()) {
			throw new ProviderNotFoundException("No HttpClientFactory service could be found in the classpath");
		}
		if (services.size() > 2) {
			throw new ProviderException(
					"More than 1 Custom HttpClientFactory service provider found. There should be only one");
		}
		if (services.size() == 2) {
			return services.stream()
					.filter(httpClientFactory -> !httpClientFactory.getClass().getName()
							.equals(DEFAULT_HTTP_CLIENT_FACTORY))
					.findFirst().get().createClient(clientIdentity);
		}
		return services.get(0).createClient(clientIdentity);
	}

}
