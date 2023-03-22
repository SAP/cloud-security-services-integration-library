/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.mtls.SSLContextFactory;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Creates a {@link CloseableHttpClient} instance. Supports certificate based
 * communication.
 */
public class DefaultHttpClientFactory implements HttpClientFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultHttpClientFactory.class);
	// reuse ssl connections
//	final ConcurrentHashMap<String, SslConnection> sslConnectionPool = new ConcurrentHashMap<>();
	final Set<String> httpClientsCreated = Collections.synchronizedSet(new HashSet<>());
	static final int MAX_CONNECTIONS_PER_ROUTE = 4; // 2 is default
	static final int MAX_CONNECTIONS = 20;
	private static final long DEFAULT_TIMEOUT = 5;
	private final RequestConfig customConfig;

	public DefaultHttpClientFactory() {
		customConfig = RequestConfig.custom()
				.setConnectTimeout(Timeout.ofSeconds(DEFAULT_TIMEOUT))
				.setConnectionRequestTimeout(Timeout.ofSeconds(DEFAULT_TIMEOUT))
//				.setSocketTimeout(Timeout.ofSeconds(DEFAULT_TIMEOUT))
				.setRedirectsEnabled(false)
				.build();
	}

//	@Override
//	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
//		String clientId = clientIdentity != null ? clientIdentity.getId() : null;
//		if (httpClientsCreated.contains(clientId)) {
//			LOGGER.warn("Application has already created HttpClient for clientId = {}, please check.", clientId);
//		}
//		httpClientsCreated.add(clientId);
//		if (clientId != null && clientIdentity.isCertificateBased()) {
//			LOGGER.info("In productive environment provide well configured HttpClientFactory service");
//			SslConnection connectionPool = sslConnectionPool.computeIfAbsent(clientId,
//					s -> new SslConnection(clientIdentity));
//			return HttpClients.custom()
//					.setDefaultRequestConfig(customConfig)
//					.setConnectionManager(connectionPool.poolingConnectionManager)
//					.setSSLContext(connectionPool.context)
//					.setSSLSocketFactory(connectionPool.sslSocketFactory)
//					.build();
//		}
//		LOGGER.warn(
//				"In productive environment provide well configured HttpClientFactory service, don't use default http client");
//		return HttpClients.custom().disableRedirectHandling().build();
//	}

	@Override
	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		String clientId = clientIdentity != null ? clientIdentity.getId() : null;
		if (httpClientsCreated.contains(clientId)) {
			LOGGER.warn("Application has already created HttpClient for clientId = {}, please check.", clientId);
		}
		httpClientsCreated.add(clientId);
		if (clientId != null && clientIdentity.isCertificateBased()) {
			LOGGER.info("In productive environment provide well configured HttpClientFactory service");
			try {
				SSLContext context = SSLContextFactory.getInstance().create(clientIdentity);
				PoolingHttpClientConnectionManager connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
						.setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
								.setSslContext(context)
								.build())
						.setDefaultSocketConfig(SocketConfig.custom()
								.setSoTimeout(Timeout.ofMinutes(1))
								.build())
						.setPoolConcurrencyPolicy(PoolConcurrencyPolicy.STRICT)
						.setConnPoolPolicy(PoolReusePolicy.LIFO)
						.setDefaultConnectionConfig(ConnectionConfig.custom()
								.setSocketTimeout(Timeout.ofSeconds(DEFAULT_TIMEOUT))
								.setConnectTimeout(Timeout.ofSeconds(DEFAULT_TIMEOUT))
								.setTimeToLive(TimeValue.ofMinutes(10))
								.build())
						.build();
			 	return HttpClients.custom().setConnectionManager(connectionManager).disableRedirectHandling().build();

			} catch (IOException | GeneralSecurityException e) {
				throw new HttpClientException(
						String.format("Couldn't set up https client for service provider %s. %s.",
								clientIdentity.getId(), e.getLocalizedMessage()));
			}
		}

		return HttpClients.custom().disableRedirectHandling().build();
	}
//
//	private static class SslConnection {
//		SSLContext context;
//		SSLConnectionSocketFactory sslSocketFactory;
//		PoolingHttpClientConnectionManager poolingConnectionManager;
//
//		public SslConnection(ClientIdentity clientIdentity) {
//			try {
//				this.context = SSLContextFactory.getInstance().create(clientIdentity);
//			} catch (IOException | GeneralSecurityException e) {
//				throw new HttpClientException(
//						String.format("Couldn't set up https client for service provider %s. %s.",
//								clientIdentity.getId(), e.getLocalizedMessage()));
//			}
//			this.sslSocketFactory = new SSLConnectionSocketFactory(context);
//			Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
//					.register("http", PlainConnectionSocketFactory.getSocketFactory())
//					.register("https", sslSocketFactory).build();
//			this.poolingConnectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
//			this.poolingConnectionManager.setDefaultMaxPerRoute(MAX_CONNECTIONS_PER_ROUTE);
//			this.poolingConnectionManager.setMaxTotal(MAX_CONNECTIONS);
//		}
//	}

}
