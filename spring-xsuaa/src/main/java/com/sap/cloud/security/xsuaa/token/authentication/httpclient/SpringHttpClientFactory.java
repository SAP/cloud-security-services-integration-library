/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication.httpclient;

import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.token.ProviderNotFoundException;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestTemplate;

import java.security.ProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * @deprecated Used only by deprecated spring-xsuaa library for backward
 *             compatibility reasons
 */
@Deprecated(forRemoval = true)
public interface SpringHttpClientFactory {

	@SuppressWarnings("unchecked")
	List<SpringHttpClientFactory> services = new ArrayList() {
		{
			ServiceLoader.load(SpringHttpClientFactory.class).forEach(this::add);
			LoggerFactory.getLogger(SpringHttpClientFactory.class).info(
					"loaded SpringHttpClientFactory service providers: {}",
					this);
		}
	};

	String DEFAULT_SPRING_HTTP_CLIENT_FACTORY = "com.sap.cloud.security.xsuaa.token.authentication.httpclient.DefaultSpringHttpClientFactory";

	/**
	 * Provides RestTemplate based on ClientIdentity details. For ClientIdentity
	 * that is certificate based it will resolve RestTemplate using the provided
	 * ClientIdentity, if the ClientIdentity wasn't provided it will return default
	 * RestTemplate.
	 *
	 * @param clientIdentity
	 *            for X.509 certificate based communication
	 *            {@link ClientCertificate} implementation of ClientIdentity
	 *            interface should be provided
	 * @return RestTemplate
	 * @throws HttpClientException
	 *             in case RestTemplate could not be setup
	 */
	default RestTemplate createRestTemplateClient(ClientIdentity clientIdentity) {
		return new RestTemplate();
	}

	static RestTemplate createRestTemplate(ClientIdentity clientIdentity) {
		if (services.isEmpty()) {
			throw new ProviderNotFoundException("No SpringHttpClientFactory service could be found in the classpath");
		}
		if (services.size() > 2) {
			throw new ProviderException(
					"More than 1 Custom SpringHttpClientFactory service provider found. There should be only one");
		}
		if (services.size() == 2) {
			return services.stream()
					.filter(httpClientFactory -> !httpClientFactory.getClass().getName()
							.equals(DEFAULT_SPRING_HTTP_CLIENT_FACTORY))
					.findFirst().get().createRestTemplateClient(clientIdentity);
		}
		return services.get(0).createRestTemplateClient(clientIdentity);
	}
}
