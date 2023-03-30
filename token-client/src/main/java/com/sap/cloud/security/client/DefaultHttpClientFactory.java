/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.mtls.SSLContextFactory;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Creates a {@link CloseableHttpClient} instance. Supports certificate based
 * communication.
 */
public class DefaultHttpClientFactory implements HttpClientFactory {
	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultHttpClientFactory.class);
	private static final Timeout DEFAULT_TIMEOUT = Timeout.ofSeconds(5);
	private static final Timeout DEFAULT_SOCKET_TIMEOUT = Timeout.ofSeconds(5);
	private static final int MAX_CONNECTIONS_PER_ROUTE = 4; // default is 2
	private static final int MAX_CONNECTIONS = 20;

	private final RequestConfig defaultRequestConfig;
	private final ConnectionConfig defaultConnectionConfig;
	// reuse ssl connections
	final ConcurrentHashMap<String, HttpClientConnectionManager> sslConnectionManagers = new ConcurrentHashMap<>();
	final Set<String> httpClientsCreated = Collections.synchronizedSet(new HashSet<>());

	public DefaultHttpClientFactory() {
		defaultRequestConfig = RequestConfig.custom()
				.setConnectionRequestTimeout(DEFAULT_TIMEOUT)
				.setRedirectsEnabled(false)
				.build();

		defaultConnectionConfig = ConnectionConfig.custom()
				.setSocketTimeout(DEFAULT_SOCKET_TIMEOUT)
				.setConnectTimeout(DEFAULT_TIMEOUT)
				.build();
	}

	@Override
	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		String clientId = clientIdentity != null ? clientIdentity.getId() : null;
		if (httpClientsCreated.contains(clientId)) {
			LOGGER.warn("Application has already created HttpClient for clientId = {}, please check.", clientId);
		}
		httpClientsCreated.add(clientId);

		if (clientId == null || !clientIdentity.isCertificateBased()) {
			LOGGER.warn(
					"In productive environment provide well configured HttpClientFactory service, don't use default http client");
			return HttpClients.custom().disableRedirectHandling().build();
		} else {
			return createTLSClient(clientIdentity);
		}
	}

	private CloseableHttpClient createTLSClient(ClientIdentity clientIdentity) {
		SSLContext context;
		try {
			context = SSLContextFactory.getInstance().create(clientIdentity);
		} catch (IOException | GeneralSecurityException e) {
			throw new HttpClientException(
					String.format("Couldn't set up https client for service provider %s. %s.",
							clientIdentity.getId(), e.getLocalizedMessage()));
		}

		HttpClientConnectionManager connectionManager = sslConnectionManagers.computeIfAbsent(clientIdentity.getId(),
				cid -> PoolingHttpClientConnectionManagerBuilder.create()
						.setDefaultConnectionConfig(defaultConnectionConfig)
						.setMaxConnPerRoute(MAX_CONNECTIONS_PER_ROUTE)
						.setMaxConnTotal(MAX_CONNECTIONS)
						.setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
								.setTlsVersions(TLS.V_1_3)
								.setSslContext(context)
								.build())
						.build());

		return HttpClients.custom()
				.setDefaultRequestConfig(defaultRequestConfig)
				.setConnectionManager(connectionManager)
				.build();
	}

}
