/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class IasTenantHostResolverTest {

	private static final URI BTP_API_BASE_URI = URI.create("https://api.authentication.eu10.hana.ondemand.com");
	private static final String TENANT_ID = "subscriber-tenant-123";

	@Mock
	private SecurityHttpClient mockHttpClient;

	private IasTenantHostResolver cut;

	@BeforeEach
	void setup() {
		cut = new IasTenantHostResolver(BTP_API_BASE_URI, mockHttpClient);
	}

	@Test
	void resolve_extractsSubdomainFromTokenEndpoint() throws IOException {
		String responseBody = """
				{"token_endpoint": "https://subscriber.accounts.ondemand.com/oauth2/token"}""";
		mockResponse(200, responseBody);

		String subdomain = cut.resolve(TENANT_ID);

		assertThat(subdomain).isEqualTo("subscriber");
	}

	@Test
	void resolve_callsCorrectEndpoint() throws IOException {
		String responseBody = """
				{"token_endpoint": "https://sub.accounts.ondemand.com/oauth2/token"}""";
		mockResponse(200, responseBody);

		cut.resolve(TENANT_ID);

		ArgumentCaptor<SecurityHttpRequest> requestCaptor = ArgumentCaptor.forClass(SecurityHttpRequest.class);
		verify(mockHttpClient).execute(requestCaptor.capture());
		SecurityHttpRequest request = requestCaptor.getValue();

		assertThat(request.getMethod()).isEqualTo("GET");
		assertThat(request.getUri().toString())
				.isEqualTo("https://api.authentication.eu10.hana.ondemand.com/sap/rest/tenantLoginInfo?id=subscriber-tenant-123");
	}

	@Test
	void resolve_cachesResult() throws IOException {
		String responseBody = """
				{"token_endpoint": "https://cached.accounts.ondemand.com/oauth2/token"}""";
		mockResponse(200, responseBody);

		String first = cut.resolve(TENANT_ID);
		String second = cut.resolve(TENANT_ID);

		assertThat(first).isEqualTo("cached");
		assertThat(second).isEqualTo("cached");
		verify(mockHttpClient, times(1)).execute(any());
	}

	@Test
	void resolve_errorResponse_throwsException() throws IOException {
		mockResponse(404, "Not found");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining("HTTP 404")
				.hasMessageContaining(TENANT_ID);
	}

	@Test
	void resolve_ioException_throwsOAuth2ServiceException() throws IOException {
		when(mockHttpClient.execute(any())).thenThrow(new IOException("Connection refused"));

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(OAuth2ServiceException.class)
				.hasMessageContaining("Connection refused");
	}

	@Test
	void clearCache_removesEntries() throws IOException {
		String responseBody = """
				{"token_endpoint": "https://sub.accounts.ondemand.com/oauth2/token"}""";
		mockResponse(200, responseBody);

		cut.resolve(TENANT_ID);
		cut.clearCache();
		cut.resolve(TENANT_ID);

		verify(mockHttpClient, times(2)).execute(any());
	}

	@Test
	void resolve_cachingDisabled_callsBackendEveryTime() throws IOException {
		IasTenantHostCacheConfiguration disabled = IasTenantHostCacheConfiguration.builder()
				.enabled(false)
				.build();
		IasTenantHostResolver disabledCut = new IasTenantHostResolver(BTP_API_BASE_URI, mockHttpClient, disabled);
		String responseBody = """
				{"token_endpoint": "https://nocache.accounts.ondemand.com/oauth2/token"}""";
		mockResponse(200, responseBody);

		disabledCut.resolve(TENANT_ID);
		disabledCut.resolve(TENANT_ID);
		disabledCut.resolve(TENANT_ID);

		verify(mockHttpClient, times(3)).execute(any());
	}

	@Test
	void resolve_cachingDisabled_clearCacheIsNoop() throws IOException {
		IasTenantHostCacheConfiguration disabled = IasTenantHostCacheConfiguration.builder()
				.enabled(false)
				.build();
		IasTenantHostResolver disabledCut = new IasTenantHostResolver(BTP_API_BASE_URI, mockHttpClient, disabled);

		disabledCut.clearCache(); // must not throw
	}

	@Test
	void resolve_errorResponse_isNotCached() throws IOException {
		mockResponse(500, "boom");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID)).isInstanceOf(OAuth2ServiceException.class);
		assertThatThrownBy(() -> cut.resolve(TENANT_ID)).isInstanceOf(OAuth2ServiceException.class);

		verify(mockHttpClient, times(2)).execute(any());
	}

	@Test
	void getCacheConfiguration_returnsConfiguredInstance() {
		IasTenantHostCacheConfiguration custom = IasTenantHostCacheConfiguration.builder()
				.ttl(Duration.ofMinutes(15))
				.maxSize(50)
				.build();
		IasTenantHostResolver customCut = new IasTenantHostResolver(BTP_API_BASE_URI, mockHttpClient, custom);

		assertThat(customCut.getCacheConfiguration()).isSameAs(custom);
	}

	@Test
	void extractSubdomainFromResponse_handlesVariousFormats() {
		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(
				"""
				{"token_endpoint": "https://mycompany.accounts.ondemand.com/oauth2/token"}"""))
				.isEqualTo("mycompany");

		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(
				"""
				{"token_endpoint": "https://deep-sub.accounts.cloud.sap/oauth2/token"}"""))
				.isEqualTo("deep-sub");
	}

	private void mockResponse(int statusCode, String body) throws IOException {
		SecurityHttpResponse response = new SecurityHttpResponse(statusCode, Map.of(), body);
		when(mockHttpClient.execute(any())).thenReturn(response);
	}
}
