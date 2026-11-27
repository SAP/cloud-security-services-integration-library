/**
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class TokenServiceSubdomainTest {

	private static final URI TOKEN_ENDPOINT = URI.create("https://tenant-a.example.com/oauth/token");
	private static final ClientCredentials CLIENT = new ClientCredentials("client-id", "client-secret");

	@ParameterizedTest
	@MethodSource("grantAndCacheModes")
	void rejectsInvalidSubdomainsBeforeRequest(Grant grant, CacheMode cacheMode) {
		RecordingTokenService service = new RecordingTokenService(cacheMode.configuration);
		for (String subdomain : List.of("tenant.example", "tenant/", "tenant//", "tenant?", "tenant#",
				"tenant@other", "tenant:8080", "tenant\\", "tenant%2F", "tenant_name", "-tenant", "tenant-",
				" tenant", "tenant\n", "täst", "a".repeat(64))) {
			assertThatIllegalArgumentException().isThrownBy(() -> request(service, grant, cacheMode, subdomain));
		}
		assertThat(service.requests).isEmpty();
	}

	@ParameterizedTest
	@MethodSource("grantAndCacheModes")
	void preservesValidSubdomainsAndBlankFallbacks(Grant grant, CacheMode cacheMode) throws OAuth2ServiceException {
		for (String subdomain : new String[] { "tenant-b", "Tenant-123", "a", "a".repeat(63), null, "", " \t\n" }) {
			RecordingTokenService service = new RecordingTokenService(cacheMode.configuration);
			assertThat(request(service, grant, cacheMode, subdomain).getAccessToken()).isEqualTo("token");
			URI expected = subdomain == null || subdomain.trim().isEmpty() ? TOKEN_ENDPOINT
					: URI.create("https://" + subdomain + ".example.com/oauth/token");
			assertThat(service.requests).containsExactly(expected);
		}
	}

	static Stream<Arguments> grantAndCacheModes() {
		return Stream.of(Grant.values()).flatMap(grant -> Stream.of(CacheMode.values())
				.map(cacheMode -> Arguments.of(grant, cacheMode)));
	}

	private OAuth2TokenResponse request(RecordingTokenService service, Grant grant, CacheMode cacheMode,
			String subdomain) throws OAuth2ServiceException {
		return switch (grant) {
			case CLIENT_CREDENTIALS -> service.retrieveAccessTokenViaClientCredentialsGrant(
					TOKEN_ENDPOINT, CLIENT, null, subdomain, null, cacheMode.disableCacheForRequest);
			case PASSWORD -> service.retrieveAccessTokenViaPasswordGrant(
					TOKEN_ENDPOINT, CLIENT, "user", "password", subdomain, null, cacheMode.disableCacheForRequest);
			case REFRESH_TOKEN -> service.retrieveAccessTokenViaRefreshToken(
					TOKEN_ENDPOINT, CLIENT, "refresh-token", subdomain, cacheMode.disableCacheForRequest);
			case JWT_BEARER -> service.retrieveAccessTokenViaJwtBearerTokenGrant(
					TOKEN_ENDPOINT, CLIENT, "assertion", subdomain, null, cacheMode.disableCacheForRequest);
		};
	}

	private enum Grant {
		CLIENT_CREDENTIALS, PASSWORD, REFRESH_TOKEN, JWT_BEARER
	}

	private enum CacheMode {
		CACHED(TokenCacheConfiguration.defaultConfiguration(), false),
		REQUEST_DISABLED(TokenCacheConfiguration.defaultConfiguration(), true),
		DISABLED(TokenCacheConfiguration.cacheDisabled(), false);

		private final TokenCacheConfiguration configuration;
		private final boolean disableCacheForRequest;

		CacheMode(TokenCacheConfiguration configuration, boolean disableCacheForRequest) {
			this.configuration = configuration;
			this.disableCacheForRequest = disableCacheForRequest;
		}
	}

	private static class RecordingTokenService extends AbstractOAuth2TokenService {
		private final List<URI> requests = new ArrayList<>();

		RecordingTokenService(TokenCacheConfiguration configuration) {
			super(configuration);
		}

		@Override
		protected OAuth2TokenResponse requestAccessToken(URI uri, HttpHeaders headers, Map<String, String> parameters) {
			requests.add(uri);
			return new OAuth2TokenResponse("token", 600L, null);
		}
	}
}
