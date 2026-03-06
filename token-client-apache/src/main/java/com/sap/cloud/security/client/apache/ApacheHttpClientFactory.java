/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client.apache;

import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpClientFactory;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Factory for creating Apache HttpClient based SecurityHttpClient instances.
 * This implementation has priority 100, making it override the default Java HttpClient
 * when available on the classpath.
 */
public class ApacheHttpClientFactory implements SecurityHttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(ApacheHttpClientFactory.class);
	private static final int DEFAULT_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(5);
	private static final int DEFAULT_SOCKET_TIMEOUT = (int) TimeUnit.SECONDS.toMillis(30);
	private static final int MAX_CONNECTIONS_PER_ROUTE = 20;
	private static final int MAX_CONNECTIONS = 200;

	private final ConcurrentHashMap<String, SslConnection> sslConnectionPool = new ConcurrentHashMap<>();
	private final org.apache.http.client.config.RequestConfig requestConfig;

	public ApacheHttpClientFactory() {
		requestConfig = org.apache.http.client.config.RequestConfig.custom()
				.setConnectTimeout(DEFAULT_TIMEOUT)
				.setConnectionRequestTimeout(DEFAULT_TIMEOUT)
				.setSocketTimeout(DEFAULT_SOCKET_TIMEOUT)
				.setRedirectsEnabled(false)
				.build();
	}

	@Override
	public SecurityHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		String clientId = clientIdentity != null ? clientIdentity.getId() : null;
		HttpClientBuilder httpClientBuilder = HttpClients.custom().setDefaultRequestConfig(requestConfig);

		if (clientId != null && clientIdentity.isCertificateBased()) {
			LOGGER.debug("Creating mTLS Apache HTTP client for {}", clientId);
			SslConnection connectionPool = sslConnectionPool.computeIfAbsent(clientId,
					s -> new SslConnection(clientIdentity));
			CloseableHttpClient httpClient = httpClientBuilder
					.setConnectionManager(connectionPool.poolingConnectionManager)
					.setSSLContext(connectionPool.context)
					.setSSLSocketFactory(connectionPool.sslSocketFactory)
					.build();
			return new ApacheHttpClientAdapter(httpClient);
		}

		CloseableHttpClient httpClient = httpClientBuilder.build();
		return new ApacheHttpClientAdapter(httpClient);
	}

	@Override
	public int getPriority() {
		return 100; // Higher priority than Java HttpClient (0)
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
						String.format("Couldn't set up HTTPS client for service provider %s: %s",
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
