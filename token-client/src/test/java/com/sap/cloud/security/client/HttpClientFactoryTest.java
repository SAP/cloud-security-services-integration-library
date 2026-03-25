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
	public void create() {
		CloseableHttpClient cut = HttpClientFactory.create(new ClientCredentials("clientId", "secret"));
		assertThat(cut).isNotNull();
		// HttpClientFactory is deprecated and uses DefaultHttpClientFactory
		assertThat(cut.getClass().getName()).contains("InternalHttpClient");
	}

}