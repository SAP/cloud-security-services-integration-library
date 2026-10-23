/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;

import org.json.JSONObject;
import org.json.JSONTokener;
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
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
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
		mockResponse(200, activeResponse("https://subscriber.accounts.ondemand.com/oauth2/token"));

		String subdomain = cut.resolve(TENANT_ID);

		assertThat(subdomain).isEqualTo("subscriber");
	}

	@Test
	void resolve_callsCorrectEndpoint() throws IOException {
		mockResponse(200, activeResponse("https://sub.accounts.ondemand.com/oauth2/token"));

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
		mockResponse(200, activeResponse("https://cached.accounts.ondemand.com/oauth2/token"));

		String first = cut.resolve(TENANT_ID);
		String second = cut.resolve(TENANT_ID);

		assertThat(first).isEqualTo("cached");
		assertThat(second).isEqualTo("cached");
		verify(mockHttpClient, times(1)).execute(any());
	}

	@Test
	void resolve_http404_mapsToTenantNotFound() throws IOException {
		mockResponse(404, "Not found");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> {
					IasTenantHostResolutionException ex = (IasTenantHostResolutionException) e;
					assertThat(ex.getErrorCode())
							.isEqualTo(IasTenantHostResolutionException.ErrorCode.TENANT_NOT_FOUND);
					assertThat(ex.getHttpStatusCode()).isEqualTo(404);
				})
				.hasMessageContaining(TENANT_ID);
	}

	@Test
	void resolve_http400_mapsToInvalidRequest() throws IOException {
		mockResponse(400, "Bad request");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.INVALID_REQUEST));
	}

	@Test
	void resolve_http401_mapsToAuthenticationFailed() throws IOException {
		mockResponse(401, "Unauthorized");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.AUTHENTICATION_FAILED));
	}

	@Test
	void resolve_http424_mapsToUpstreamUnavailable() throws IOException {
		mockResponse(424, "Failed dependency");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.UPSTREAM_UNAVAILABLE));
	}

	@Test
	void resolve_http500_mapsToUpstreamMisconfigured() throws IOException {
		mockResponse(500, "Internal server error");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.UPSTREAM_MISCONFIGURED));
	}

	@Test
	void resolve_http503_mapsToUpstreamUnavailable() throws IOException {
		mockResponse(503, "Service unavailable");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.UPSTREAM_UNAVAILABLE));
	}

	@Test
	void resolve_ioException_mapsToUpstreamUnavailable() throws IOException {
		when(mockHttpClient.execute(any())).thenThrow(new IOException("Connection refused"));

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> {
					IasTenantHostResolutionException ex = (IasTenantHostResolutionException) e;
					assertThat(ex.getErrorCode())
							.isEqualTo(IasTenantHostResolutionException.ErrorCode.UPSTREAM_UNAVAILABLE);
					assertThat(ex.getHttpStatusCode()).isZero();
				});
	}

	@Test
	void resolve_statusInactive_mapsToTenantInactive() throws IOException {
		mockResponse(200, """
				{"status": "INACTIVE", "token_endpoint": "https://sub.accounts.ondemand.com/oauth2/token", "error_details": "tenant deactivated"}""");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.TENANT_INACTIVE))
				.hasMessageContaining("tenant deactivated");
	}

	@Test
	void resolve_statusNotrust_mapsToNotTrusted() throws IOException {
		mockResponse(200, """
				{"status": "NOTRUST", "token_endpoint": "https://sub.accounts.ondemand.com/oauth2/token"}""");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.NOT_TRUSTED));
	}

	@Test
	void resolve_statusError_mapsToTenantInfoError_withDetails() throws IOException {
		mockResponse(200, """
				{"status": "ERROR", "token_endpoint": "https://sub.accounts.ondemand.com/oauth2/token", "error_details": "registry lookup failed"}""");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR))
				.hasMessageContaining("registry lookup failed");
	}

	@Test
	void resolve_missingStatus_mapsToTenantInfoError() throws IOException {
		mockResponse(200, """
				{"token_endpoint": "https://sub.accounts.ondemand.com/oauth2/token"}""");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR));
	}

	@Test
	void resolve_malformedJson_mapsToTenantInfoError() throws IOException {
		mockResponse(200, "not-json");

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR));
	}

	@Test
	void resolve_invalidTenantId_rejectedBeforeRequest() throws IOException {
		assertThatThrownBy(() -> cut.resolve("bad tenant id!"))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.INVALID_REQUEST));
		verifyNoInteractions(mockHttpClient);
	}

	@Test
	void resolve_tenantIdWithQueryMetacharacters_isEncoded() throws IOException {
		// validated format is alphanumeric/underscore/hyphen, so encode() is belt-and-braces;
		// a tenant ID that passes the format check must produce a clean query string
		mockResponse(200, activeResponse("https://sub.accounts.ondemand.com/oauth2/token"));

		cut.resolve("abc-123_def");

		ArgumentCaptor<SecurityHttpRequest> requestCaptor = ArgumentCaptor.forClass(SecurityHttpRequest.class);
		verify(mockHttpClient).execute(requestCaptor.capture());
		assertThat(requestCaptor.getValue().getUri().toString())
				.isEqualTo("https://api.authentication.eu10.hana.ondemand.com/sap/rest/tenantLoginInfo?id=abc-123_def");
	}

	@Test
	void resolve_localInformationOnly_sendsFlag() throws IOException {
		IasTenantHostCacheConfiguration localOnly = IasTenantHostCacheConfiguration.builder()
				.localInformationOnly(true)
				.build();
		IasTenantHostResolver localOnlyCut = new IasTenantHostResolver(BTP_API_BASE_URI, mockHttpClient, localOnly);
		mockResponse(200, activeResponse("https://sub.accounts.ondemand.com/oauth2/token"));

		localOnlyCut.resolve(TENANT_ID);

		ArgumentCaptor<SecurityHttpRequest> requestCaptor = ArgumentCaptor.forClass(SecurityHttpRequest.class);
		verify(mockHttpClient).execute(requestCaptor.capture());
		assertThat(requestCaptor.getValue().getUri().toString())
				.isEqualTo("https://api.authentication.eu10.hana.ondemand.com/sap/rest/tenantLoginInfo?id=subscriber-tenant-123&localInformationOnly=true");
	}

	@Test
	void clearCache_removesEntries() throws IOException {
		mockResponse(200, activeResponse("https://sub.accounts.ondemand.com/oauth2/token"));

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
		mockResponse(200, activeResponse("https://nocache.accounts.ondemand.com/oauth2/token"));

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

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class);
		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class);

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
	void constructor_rejectsNonHttpsBaseUri() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new IasTenantHostResolver(
						URI.create("http://api.authentication.eu10.hana.ondemand.com"), mockHttpClient))
				.withMessageContaining("HTTPS");
	}

	@Test
	void extractSubdomainFromResponse_handlesVariousFormats() {
		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(json(
				"""
				{"status": "ACTIVE", "token_endpoint": "https://mycompany.accounts.ondemand.com/oauth2/token"}""")))
				.isEqualTo("mycompany");

		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(json(
				"""
				{"status": "ACTIVE", "token_endpoint": "https://deep-sub.accounts.cloud.sap/oauth2/token"}""")))
				.isEqualTo("deep-sub");
	}

	@Test
	void extractSubdomainFromResponse_rejectsNonHttps() {
		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(json(
				"""
				{"status": "ACTIVE", "token_endpoint": "http://sub.accounts.ondemand.com/oauth2/token"}""")))
				.isNull();
	}

	@Test
	void extractSubdomainFromResponse_rejectsMissingHost() {
		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(json(
				"""
				{"status": "ACTIVE", "token_endpoint": "https://"}""")))
				.isNull();
	}

	@Test
	void extractSubdomainFromResponse_rejectsMalformed() {
		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(json(
				"""
				{"status": "ACTIVE", "token_endpoint": "://broken"}""")))
				.isNull();
		assertThat(IasTenantHostResolver.extractSubdomainFromResponse(json(
				"""
				{"status": "ACTIVE"}""")))
				.isNull();
	}

	@Test
	void resolve_rejectsInvalidDnsLabelFromResponse() throws IOException {
		// a host whose first label violates DNS label rules must not be used to rewrite the IAS host
		mockResponse(200, activeResponse("https://sub_1.accounts.ondemand.com/oauth2/token"));

		assertThatThrownBy(() -> cut.resolve(TENANT_ID))
				.isInstanceOf(IasTenantHostResolutionException.class)
				.satisfies(e -> assertThat(((IasTenantHostResolutionException) e).getErrorCode())
						.isEqualTo(IasTenantHostResolutionException.ErrorCode.TENANT_INFO_ERROR));
	}

	@Test
	void resolve_usesProvidedSecurityCache() throws IOException {
		RecordingCache cache = new RecordingCache();
		IasTenantHostResolver cutWithCache = new IasTenantHostResolver(BTP_API_BASE_URI, mockHttpClient,
				IasTenantHostCacheConfiguration.defaultConfiguration(), cache);
		mockResponse(200, activeResponse("https://cached.accounts.ondemand.com/oauth2/token"));

		cutWithCache.resolve(TENANT_ID);
		cutWithCache.resolve(TENANT_ID);

		verify(mockHttpClient, times(1)).execute(any());
		assertThat(cache.store)
				.containsKey(CacheKeys.build(CacheKeys.NAMESPACE_TENANT_HOSTS, TENANT_ID));
	}

	@Test
	void clearCache_clearsProvidedSecurityCache() throws IOException {
		RecordingCache cache = new RecordingCache();
		IasTenantHostResolver cutWithCache = new IasTenantHostResolver(BTP_API_BASE_URI, mockHttpClient,
				IasTenantHostCacheConfiguration.defaultConfiguration(), cache);
		mockResponse(200, activeResponse("https://cached.accounts.ondemand.com/oauth2/token"));

		cutWithCache.resolve(TENANT_ID);
		cutWithCache.clearCache();

		assertThat(cache.store).isEmpty();
	}

	private static String activeResponse(String tokenEndpoint) {
		return """
				{"status": "ACTIVE", "token_endpoint": "%s"}""".formatted(tokenEndpoint);
	}

	private static JSONObject json(String raw) {
		return new JSONObject(new JSONTokener(raw));
	}

	private void mockResponse(int statusCode, String body) throws IOException {
		SecurityHttpResponse response = new SecurityHttpResponse(statusCode, Map.of(), body);
		when(mockHttpClient.execute(any())).thenReturn(response);
	}

	/** Minimal in-memory SecurityCache for tests. */
	static class RecordingCache implements SecurityCache<String, String> {
		final ConcurrentHashMap<String, String> store = new ConcurrentHashMap<>();

		@Override
		public java.util.Optional<String> get(String key) {
			return java.util.Optional.ofNullable(store.get(key));
		}

		@Override
		public void set(String key, String value, Duration ttl) {
			store.put(key, value);
		}

		@Override
		public void delete(String key) {
			store.remove(key);
		}

		@Override
		public void clear() {
			store.clear();
		}
	}
}
