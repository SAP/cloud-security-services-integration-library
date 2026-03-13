/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.mtls.SSLContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Factory for creating Java 11 HttpClient based SecurityHttpClient instances.
 * This is the default implementation with priority 0.
 */
public class JavaHttpClientFactory implements SecurityHttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(JavaHttpClientFactory.class);
	private static final int DEFAULT_TIMEOUT_SECONDS = 5;
	private static final int DEFAULT_SOCKET_TIMEOUT_SECONDS = 30;

	@Override
	public SecurityHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		try {
			HttpClient.Builder builder = HttpClient.newBuilder()
					.connectTimeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS))
					.followRedirects(HttpClient.Redirect.NEVER);

			if (clientIdentity != null && clientIdentity.isCertificateBased()) {
				LOGGER.debug("Creating mTLS HTTP client for {}", clientIdentity.getId());
				SSLContext sslContext = SSLContextFactory.getInstance().create(clientIdentity);
				builder.sslContext(sslContext);
			}

			HttpClient httpClient = builder.build();
			return new JavaHttpClientAdapter(httpClient, DEFAULT_SOCKET_TIMEOUT_SECONDS);

		} catch (IOException | GeneralSecurityException e) {
			throw new HttpClientException(
					String.format("Couldn't set up HTTP client: %s", e.getLocalizedMessage()), e);
		}
	}

	@Override
	public int getPriority() {
		return 0; // Default implementation
	}
}
