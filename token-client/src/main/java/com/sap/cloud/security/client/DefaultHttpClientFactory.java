/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.mtls.SSLContextFactory;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Constructs a {@link CloseableHttpClient} object. Facilitates certificate and client credentials-based
 * communication based on the identity service configuration from the binding.
 * <p>
 * HttpClient is configured with the following default values:
 * - connection and connection request timeout - 5 s
 * - socket timeout - 30 s
 * - max connections - 200
 * - max connections per route - 20
 * <p>
 * If these values do not meet your requirements, please provide your own implementation of {@link HttpClientFactory}.
 */
public class DefaultHttpClientFactory implements HttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultHttpClientFactory.class);

	private static final int DEFAULT_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(5);
	private static final int DEFAULT_SOCKET_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(30);
	private static final int MAX_CONNECTIONS_PER_ROUTE = 20; // default is 2
	private static final int MAX_CONNECTIONS = 200;
	private final ConcurrentHashMap<String, SslConnection> sslConnectionPool = new ConcurrentHashMap<>();
	private final org.apache.http.client.config.RequestConfig requestConfig;
	// reuse ssl connections
	final Set<String> httpClientsCreated = Collections.synchronizedSet(new HashSet<>());

	public DefaultHttpClientFactory() {
		requestConfig = org.apache.http.client.config.RequestConfig.custom()
				.setConnectTimeout(DEFAULT_TIMEOUT)
				.setConnectionRequestTimeout(DEFAULT_TIMEOUT)
				.setSocketTimeout(DEFAULT_SOCKET_TIMEOUT)
				.setRedirectsEnabled(false)
				.build();
	}

	@Override
	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		String clientId = clientIdentity != null ? clientIdentity.getId() : null;
		if (httpClientsCreated.contains(clientId)) {
			LOGGER.warn("Application has already created HttpClient for clientId = {}, please check.", clientId);
		}
		httpClientsCreated.add(clientId);
		HttpClientBuilder httpClientBuilder = HttpClients.custom().setDefaultRequestConfig(requestConfig);

		if (clientId != null && clientIdentity.isCertificateBased()) {
			SslConnection connectionPool = sslConnectionPool.computeIfAbsent(clientId,
					s -> new SslConnection(clientIdentity));
			return httpClientBuilder
					.setConnectionManager(connectionPool.poolingConnectionManager)
					.setSSLContext(connectionPool.context)
					.setSSLSocketFactory(connectionPool.sslSocketFactory)
					.build();
		}
		return httpClientBuilder
				.build();
	}

	private static class SslConnection {
		SSLContext context;
		SSLConnectionSocketFactory sslSocketFactory;
		PoolingHttpClientConnectionManager poolingConnectionManager;

		public SslConnection(ClientIdentity clientIdentity) {
			try {
				this.context = SSLContextFactory.getInstance().create(clientIdentity);
			} catch (IOException | GeneralSecurityException e) {
				throw new HttpClientException(
						String.format("Couldn't set up https client for service provider %s. %s.",
								clientIdentity.getId(), e.getLocalizedMessage()));
			}
			this.sslSocketFactory = new SSLConnectionSocketFactory(context);
			Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.register("https", sslSocketFactory).build();
			this.poolingConnectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
			this.poolingConnectionManager.setDefaultMaxPerRoute(MAX_CONNECTIONS_PER_ROUTE);
			this.poolingConnectionManager.setMaxTotal(MAX_CONNECTIONS);
		}
	}

}
