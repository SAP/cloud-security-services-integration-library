/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class IasTokenFlowsTest {

	private static final String IAS_BASE_URL = "https://provider.accounts.ondemand.com";

	@Mock
	private OAuth2TokenService mockTokenService;

	@Test
	void constructor_withNullTokenService_throws() {
		assertThatThrownBy(() -> new IasTokenFlows(null,
				new IasDefaultEndpoints(IAS_BASE_URL),
				new ClientCredentials("id", "secret")))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("OAuth2TokenService");
	}

	@Test
	void constructor_withNullEndpoints_throws() {
		assertThatThrownBy(() -> new IasTokenFlows(mockTokenService,
				null,
				new ClientCredentials("id", "secret")))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("IasDefaultEndpoints");
	}

	@Test
	void constructor_withNullClientIdentity_throws() {
		assertThatThrownBy(() -> new IasTokenFlows(mockTokenService,
				new IasDefaultEndpoints(IAS_BASE_URL),
				null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("ClientIdentity");
	}

	@Test
	void clientCredentialsTokenFlow_returnsNonNull() {
		ClientIdentity identity = new ClientCredentials("id", "secret");
		IasTokenFlows flows = new IasTokenFlows(mockTokenService, new IasDefaultEndpoints(IAS_BASE_URL), identity);

		assertThat(flows.clientCredentialsTokenFlow()).isNotNull();
	}

	@Test
	void jwtBearerTokenFlow_returnsNonNull() {
		ClientIdentity identity = new ClientCredentials("id", "secret");
		IasTokenFlows flows = new IasTokenFlows(mockTokenService, new IasDefaultEndpoints(IAS_BASE_URL), identity);

		assertThat(flows.jwtBearerTokenFlow()).isNotNull();
	}

	@Test
	void clientCredentialsTokenFlow_eachCallReturnsNewInstance() {
		ClientIdentity identity = new ClientCredentials("id", "secret");
		IasTokenFlows flows = new IasTokenFlows(mockTokenService, new IasDefaultEndpoints(IAS_BASE_URL), identity);

		IasClientCredentialsTokenFlow first = flows.clientCredentialsTokenFlow();
		IasClientCredentialsTokenFlow second = flows.clientCredentialsTokenFlow();

		assertThat(first).isNotSameAs(second);
	}
}
