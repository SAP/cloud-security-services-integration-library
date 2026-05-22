/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class SecurityHttpClientFactoryTest {

	@Test
	public void createClient_withClientCredentials_returnsSecurityHttpClient() {
		ClientIdentity clientId = new ClientCredentials("clientId", "secret");
		SecurityHttpClient client = SecurityHttpClientProvider.createClient(clientId);

		assertThat(client).isNotNull();
	}

	@Test
	public void createClient_withNullIdentity_returnsSecurityHttpClient() {
		SecurityHttpClient client = SecurityHttpClientProvider.createClient(null);

		assertThat(client).isNotNull();
	}

	@Test
	public void testSecurityHttpClientFactory_usesHighestPriority() {
		// TestSecurityHttpClientFactory has priority 100
		ClientIdentity clientId = new ClientCredentials("clientId", "secret");
		SecurityHttpClient client = SecurityHttpClientProvider.createClient(clientId);

		assertThat(client).isNotNull();
		// Should use TestSecurityHttpClientFactory which returns a Mockito mock
		assertThat(client.getClass().getName()).contains("MockitoMock");
	}
}
