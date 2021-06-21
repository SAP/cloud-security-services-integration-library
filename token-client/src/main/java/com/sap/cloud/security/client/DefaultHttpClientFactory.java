/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import org.apache.http.impl.client.CloseableHttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Creates a {@link CloseableHttpClient} instance. Supports certificate based communication.
 */
public class DefaultHttpClientFactory implements HttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultHttpClientFactory.class);

	public CloseableHttpClient create(OAuth2ServiceConfiguration configuration) {
		Objects.requireNonNull(configuration, "Requires oauth2 service configuration to create a default http client.");
		return null; // TODO
	}
}
