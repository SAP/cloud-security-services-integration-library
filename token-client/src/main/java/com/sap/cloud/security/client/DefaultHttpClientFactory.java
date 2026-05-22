/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
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

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of {@link HttpClientFactory} that creates Apache {@link CloseableHttpClient} instances.
 *
 * <p>HttpClient is configured with the following default values:
 * <ul>
 *   <li>Connection timeout: 5 seconds</li>
 *   <li>Connection request timeout: 5 seconds</li>
 *   <li>Socket timeout: 30 seconds</li>
 *   <li>Max connections: 200</li>
 *   <li>Max connections per route: 20</li>
 * </ul>
 *
 * <p><strong>Deprecation Notice - 3-Step Migration Plan:</strong>
 * <ul>
 *   <li><strong>Version 4.x (current):</strong> This class is deprecated but fully functional with Apache HttpClient 4.
 *       Existing code continues to work without changes.</li>
 *   <li><strong>Version 5.0.0:</strong> This class will be changed to return {@link SecurityHttpClient} instead of
 *       {@link CloseableHttpClient}. Code using this class will need to be updated.</li>
 *   <li><strong>Version 6.0.0:</strong> This class will be removed entirely.</li>
 * </ul>
 *
 * <p><strong>Recommended Migration:</strong> Use {@link SecurityHttpClientProvider#createClient(ClientIdentity)} instead,
 * which returns a {@link SecurityHttpClient} that works with the modern Java 11 HttpClient by default.
 *
 * @deprecated Since 4.0.0. Use {@link SecurityHttpClientProvider} with {@link JavaHttpClientFactory} instead.
 *             This class will change its return type in 5.0.0 and be removed in 6.0.0.
 * @see SecurityHttpClientProvider
 * @see SecurityHttpClient
 */
@Deprecated(since = "4.0.0", forRemoval = true)
public class DefaultHttpClientFactory implements HttpClientFactory {

	private static final int DEFAULT_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(5);
	private static final int DEFAULT_SOCKET_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(30);
	private static final int MAX_CONNECTIONS_PER_ROUTE = 20;
	private static final int MAX_CONNECTIONS = 200;
	private final ConcurrentHashMap<String, SslConnection> sslConnectionPool = new ConcurrentHashMap<>();
	private final org.apache.http.client.config.RequestConfig requestConfig;

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
		return httpClientBuilder.build();
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
			Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.register("https", sslSocketFactory).build();
			this.poolingConnectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
			this.poolingConnectionManager.setDefaultMaxPerRoute(MAX_CONNECTIONS_PER_ROUTE);
			this.poolingConnectionManager.setMaxTotal(MAX_CONNECTIONS);
		}
	}
}