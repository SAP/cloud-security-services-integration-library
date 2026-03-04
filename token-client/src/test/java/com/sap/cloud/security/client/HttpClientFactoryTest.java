/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCredentials;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class HttpClientFactoryTest {

	@Test
	public void create() {
		CloseableHttpClient cut = HttpClientFactory.create(new ClientCredentials("clientId", "secret"));
		assertThat(cut).isNotNull();

		// Assert that custom HttpClientFactory factory has a priority over default
		// com.sap.cloud.security.client.DefaultHttpClientFactory
		assertThat(cut.getClass().getName()).doesNotContain("InternalHttpClient");
		assertThat(cut.getClass().getName()).contains("CloseableHttpClient$MockitoMock");
	}

}