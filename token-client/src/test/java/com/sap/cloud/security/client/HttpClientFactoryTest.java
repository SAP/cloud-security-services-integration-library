/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCredentials;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class HttpClientFactoryTest {

	@Test
	public void create_prefersCustomFactoryOverDefault() {
		CloseableHttpClient cut = HttpClientFactory.create(new ClientCredentials("clientId", "secret"));
		assertThat(cut).isNotNull();
		// TestHttpClientFactory is registered via META-INF/services and returns a Mockito mock
		assertThat(cut.getClass().getName()).contains("MockitoMock");
	}

	@Test
	public void services_containsDefaultAndCustomFactory() {
		assertThat(HttpClientFactory.services).hasSize(2);
		assertThat(HttpClientFactory.services.stream()
				.map(f -> f.getClass().getName()))
				.contains("com.sap.cloud.security.client.DefaultHttpClientFactory",
						"com.sap.cloud.security.client.TestHttpClientFactory");
	}

}