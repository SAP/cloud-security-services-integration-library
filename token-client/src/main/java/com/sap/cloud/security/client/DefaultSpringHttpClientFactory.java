/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.mtls.SSLContextFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class DefaultSpringHttpClientFactory implements SpringHttpClientFactory {
	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultSpringHttpClientFactory.class);
	final Set<String> httpClientsCreated = Collections.synchronizedSet(new HashSet<>());
	final ConcurrentHashMap<String, HttpClientConnectionManager> sslConnectionManagers = new ConcurrentHashMap<>();
	private static final Timeout DEFAULT_TIMEOUT = Timeout.ofSeconds(5);
	private static final Timeout DEFAULT_SOCKET_TIMEOUT = Timeout.ofSeconds(5);
	private static final int MAX_CONNECTIONS_PER_ROUTE = 4; // default is 2
	private static final int MAX_CONNECTIONS = 20;

	@Override
	public RestTemplate createRestTemplateClient(ClientIdentity clientIdentity) {
		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
		requestFactory.setHttpClient(createClient5(clientIdentity));
		return new RestTemplate(requestFactory);
	}

	private org.apache.hc.client5.http.impl.classic.CloseableHttpClient createClient5(ClientIdentity clientIdentity)
			throws HttpClientException {
		String clientId = clientIdentity != null ? clientIdentity.getId() : null;
		if (httpClientsCreated.contains(clientId)) {
			LOGGER.warn("Application has already created HttpClient for clientId = {}, please check.", clientId);
		}
		httpClientsCreated.add(clientId);

		if (clientId == null || !clientIdentity.isCertificateBased()) {
			LOGGER.warn(
					"In productive environment provide well configured HttpClientFactory service, don't use default http client");
			return org.apache.hc.client5.http.impl.classic.HttpClients.custom().disableRedirectHandling().build();
		} else {
			return createTLSClient5(clientIdentity);
		}
	}

	private org.apache.hc.client5.http.impl.classic.CloseableHttpClient createTLSClient5(
			ClientIdentity clientIdentity) {
		final org.apache.hc.client5.http.config.RequestConfig defaultRequestConfig5;
		final org.apache.hc.client5.http.config.ConnectionConfig defaultConnectionConfig5;
		defaultRequestConfig5 = org.apache.hc.client5.http.config.RequestConfig.custom()
				.setConnectionRequestTimeout(DEFAULT_TIMEOUT)
				.setRedirectsEnabled(false)
				.build();

		defaultConnectionConfig5 = org.apache.hc.client5.http.config.ConnectionConfig.custom()
				.setSocketTimeout(DEFAULT_SOCKET_TIMEOUT)
				.setConnectTimeout(DEFAULT_TIMEOUT)
				.build();
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
						.setDefaultConnectionConfig(defaultConnectionConfig5)
						.setMaxConnPerRoute(MAX_CONNECTIONS_PER_ROUTE)
						.setMaxConnTotal(MAX_CONNECTIONS)
						.setSSLSocketFactory(SSLConnectionSocketFactoryBuilder.create()
								.setTlsVersions(TLS.V_1_3)
								.setSslContext(context)
								.build())
						.build());

		return org.apache.hc.client5.http.impl.classic.HttpClients.custom()
				.setDefaultRequestConfig(defaultRequestConfig5)
				.setConnectionManager(connectionManager)
				.build();
	}
}
