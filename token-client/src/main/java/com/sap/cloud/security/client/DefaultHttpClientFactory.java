/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.mtls.SSLContextFactory;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.util.Timeout;

/**
 * Constructs a {@link CloseableHttpClient} object. Facilitates certificate and client credentials-based communication
 * based on the identity service configuration from the binding.
 * <p>
 * HttpClient is configured with the following default values: - connection and connection request timeout - 5 s -
 * socket timeout - 30 s - max connections - 200 - max connections per route - 20
 * <p>
 * If these values do not meet your requirements, please provide your own implementation of {@link HttpClientFactory}.
 */
public class DefaultHttpClientFactory implements HttpClientFactory {

	private static final int DEFAULT_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(5);
	private static final int DEFAULT_SOCKET_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(30);
	private static final int MAX_CONNECTIONS_PER_ROUTE = 20; // default is 2
	private static final int MAX_CONNECTIONS = 200;
	private final ConcurrentHashMap<String, SslConnection> sslConnectionPool = new ConcurrentHashMap<>();
	private final RequestConfig requestConfig;
	private final ConnectionConfig connectionConfig;

	public DefaultHttpClientFactory() {
		requestConfig = RequestConfig.custom()
				.setConnectTimeout(Timeout.ofMilliseconds(DEFAULT_TIMEOUT))
				.setConnectionRequestTimeout(Timeout.ofMilliseconds(DEFAULT_TIMEOUT))
				.setResponseTimeout(Timeout.ofMilliseconds(DEFAULT_SOCKET_TIMEOUT))
				.setRedirectsEnabled(false)
				.build();

		connectionConfig = ConnectionConfig.custom()
				.setConnectTimeout(Timeout.ofMilliseconds(DEFAULT_TIMEOUT))
				.setSocketTimeout(Timeout.ofMilliseconds(DEFAULT_SOCKET_TIMEOUT))
				.build();
	}

	@Override
	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		String clientId = clientIdentity != null ? clientIdentity.getId() : null;
		HttpClientBuilder httpClientBuilder = HttpClients.custom().setDefaultRequestConfig(requestConfig);

		if (clientId != null && clientIdentity.isCertificateBased()) {
			SslConnection connectionPool = sslConnectionPool.computeIfAbsent(clientId,
					s -> new SslConnection(clientIdentity, connectionConfig));
			return httpClientBuilder
					.setConnectionManager(connectionPool.connectionManager)
					.build();
		}
		return httpClientBuilder
				.build();
	}

	private static class SslConnection {
		HttpClientConnectionManager connectionManager;

		public SslConnection(ClientIdentity clientIdentity, ConnectionConfig connectionConfig) {
			SSLContext context;
			try {
				context = SSLContextFactory.getInstance().create(clientIdentity);
			} catch (IOException | GeneralSecurityException e) {
				throw new HttpClientException(
						"Couldn't set up https client for service provider %s. %s.".formatted(
								clientIdentity.getId(), e.getLocalizedMessage()));
			}

			this.connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
					.setDefaultConnectionConfig(connectionConfig)
					.setMaxConnPerRoute(MAX_CONNECTIONS_PER_ROUTE)
					.setMaxConnTotal(MAX_CONNECTIONS)
					.setTlsSocketStrategy(new DefaultClientTlsStrategy(
							context,
							new String[] { TLS.V_1_2.id, TLS.V_1_3.id },
							null,
							null,
							null))
					.build();
		}
	}

}
