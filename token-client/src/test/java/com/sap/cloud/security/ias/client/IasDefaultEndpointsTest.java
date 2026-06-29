/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IasDefaultEndpointsTest {

	private static final String IAS_BASE_URL = "https://provider.accounts.ondemand.com";

	@Test
	void getTokenEndpoint_returnsOAuth2TokenPath() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints(IAS_BASE_URL);
		assertThat(endpoints.getTokenEndpoint())
				.isEqualTo(URI.create("https://provider.accounts.ondemand.com/oauth2/token"));
	}

	@Test
	void getAuthorizeEndpoint_returnsOAuth2AuthorizePath() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints(IAS_BASE_URL);
		assertThat(endpoints.getAuthorizeEndpoint())
				.isEqualTo(URI.create("https://provider.accounts.ondemand.com/oauth2/authorize"));
	}

	@Test
	void getJwksUri_returnsOAuth2CertsPath() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints(IAS_BASE_URL);
		assertThat(endpoints.getJwksUri())
				.isEqualTo(URI.create("https://provider.accounts.ondemand.com/oauth2/certs"));
	}

	@Test
	void constructor_withTrailingSlash_stripsIt() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints("https://provider.accounts.ondemand.com/");
		assertThat(endpoints.getTokenEndpoint())
				.isEqualTo(URI.create("https://provider.accounts.ondemand.com/oauth2/token"));
	}

	@Test
	void constructor_withNullUri_throws() {
		assertThatThrownBy(() -> new IasDefaultEndpoints((String) null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void withSubdomain_replacesFirstHostLabel() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints(IAS_BASE_URL);
		IasDefaultEndpoints subscriberEndpoints = endpoints.withSubdomain("subscriber");

		assertThat(subscriberEndpoints.getTokenEndpoint())
				.isEqualTo(URI.create("https://subscriber.accounts.ondemand.com/oauth2/token"));
		assertThat(subscriberEndpoints.getBaseUri())
				.isEqualTo(URI.create("https://subscriber.accounts.ondemand.com"));
	}

	@Test
	void withSubdomain_nullOrBlank_returnsSameInstance() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints(IAS_BASE_URL);
		assertThat(endpoints.withSubdomain(null)).isSameAs(endpoints);
		assertThat(endpoints.withSubdomain("")).isSameAs(endpoints);
		assertThat(endpoints.withSubdomain("  ")).isSameAs(endpoints);
	}

	@Test
	void withSubdomain_preservesPort() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints("https://provider.accounts.ondemand.com:8443");
		IasDefaultEndpoints subscriberEndpoints = endpoints.withSubdomain("subscriber");

		assertThat(subscriberEndpoints.getTokenEndpoint())
				.isEqualTo(URI.create("https://subscriber.accounts.ondemand.com:8443/oauth2/token"));
	}

	@Test
	void getBaseUri_returnsConfiguredUri() {
		IasDefaultEndpoints endpoints = new IasDefaultEndpoints(IAS_BASE_URL);
		assertThat(endpoints.getBaseUri()).isEqualTo(URI.create(IAS_BASE_URL));
	}
}
