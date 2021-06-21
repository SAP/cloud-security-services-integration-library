/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.ProviderNotFoundException;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Represents a {@link CloseableHttpClient} creation interface.
 */
public interface HttpClientFactory {
	List<HttpClientFactory> services = new ArrayList() {
		{
			ServiceLoader.load(HttpClientFactory.class).forEach(this::add);
			LoggerFactory.getLogger(HttpClientFactory.class).info("loaded HttpClientFactory service providers: {}", this);
		}
	};

	/**
	 * Returns a ClosableHttpClient for the given oauth2 service configuration.
	 *
	 * @param config
	 *            the service configuration, e.g. from VCAP_SERVICES
	 * @return the new rest client
	 */
	default CloseableHttpClient create(OAuth2ServiceConfiguration config) {
		if (services.isEmpty()) {
			throw new ProviderNotFoundException("No TokenFactory implementation found in the classpath");
		}
		return services.get(0).create(config);
	}

}
