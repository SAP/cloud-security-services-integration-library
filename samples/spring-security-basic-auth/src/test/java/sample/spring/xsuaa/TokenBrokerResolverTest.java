/**
 * SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package sample.spring.xsuaa;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.xsuaa.client.AbstractOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EmptySource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class TokenBrokerResolverTest {

	private final RecordingTokenService tokenService = new RecordingTokenService();
	private final ConcurrentMapCache cache = new ConcurrentMapCache("token-broker-test");
	private final TokenBrokerResolver resolver = new TokenBrokerResolver(new XsuaaTokenFlows(tokenService,
			new XsuaaDefaultEndpoints("https://tenant-a.example.com", null),
			new ClientCredentials("client-id", "client-secret")), cache);

	@ParameterizedTest
	@ValueSource(strings = { "tenant.example", "tenant/", "tenant?", "tenant#", "tenant@other", "tenant:8080",
			"tenant%2F", "tenant_name", "-tenant", "tenant-", " tenant", "tenant\n", "täst" })
	void rejectsInvalidHeaderAndParameterValues(String subdomain) {
		MockHttpServletRequest headerRequest = basicAuthRequest();
		headerRequest.addHeader(TokenBrokerResolver.ZONE_ID_HEADER, subdomain);
		assertThat(resolver.resolve(headerRequest)).isNull();

		MockHttpServletRequest parameterRequest = basicAuthRequest();
		parameterRequest.addHeader(TokenBrokerResolver.ZONE_ID_HEADER, "tenant-b");
		parameterRequest.setParameter(TokenBrokerResolver.ZONE_ID_HEADER, subdomain);
		assertThat(resolver.resolve(parameterRequest)).isNull();

		assertThat(tokenService.requests).isEmpty();
		assertThat(cache.getNativeCache()).isEmpty();
	}

	@Test
	void resolvesAndCachesValidHeaderValue() {
		MockHttpServletRequest request = basicAuthRequest();
		request.addHeader(TokenBrokerResolver.ZONE_ID_HEADER, "tenant-b");
		assertThat(resolver.resolve(request)).isEqualTo("token");
		assertThat(resolver.resolve(request)).isEqualTo("token");
		assertThat(tokenService.requests).containsExactly(URI.create("https://tenant-b.example.com/oauth/token"));
	}

	@Test
	void parameterTakesPrecedenceOverHeader() {
		MockHttpServletRequest request = basicAuthRequest();
		request.addHeader(TokenBrokerResolver.ZONE_ID_HEADER, "tenant-c");
		request.setParameter(TokenBrokerResolver.ZONE_ID_HEADER, "tenant-b");
		assertThat(resolver.resolve(request)).isEqualTo("token");
		assertThat(tokenService.requests).containsExactly(URI.create("https://tenant-b.example.com/oauth/token"));
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { " ", "\t\r\n" })
	void preservesDefaultTenantForBlankValues(String subdomain) {
		MockHttpServletRequest request = basicAuthRequest();
		if (subdomain != null) {
			request.addHeader(TokenBrokerResolver.ZONE_ID_HEADER, subdomain);
		}
		assertThat(resolver.resolve(request)).isEqualTo("token");
		assertThat(tokenService.requests).containsExactly(URI.create("https://tenant-a.example.com/oauth/token"));
	}

	@ParameterizedTest
	@EmptySource
	@ValueSource(strings = { " ", "\t\r\n" })
	void blankParameterTakesPrecedenceOverHeader(String subdomain) {
		MockHttpServletRequest request = basicAuthRequest();
		request.addHeader(TokenBrokerResolver.ZONE_ID_HEADER, "tenant-b");
		request.setParameter(TokenBrokerResolver.ZONE_ID_HEADER, subdomain);
		assertThat(resolver.resolve(request)).isEqualTo("token");
		assertThat(tokenService.requests).containsExactly(URI.create("https://tenant-a.example.com/oauth/token"));
	}

	private MockHttpServletRequest basicAuthRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(org.springframework.http.HttpHeaders.AUTHORIZATION, "Basic dXNlcjpwYXNzd29yZA==");
		return request;
	}

	private static class RecordingTokenService extends AbstractOAuth2TokenService {
		private final List<URI> requests = new ArrayList<>();

		RecordingTokenService() {
			super(TokenCacheConfiguration.cacheDisabled());
		}

		@Override
		protected OAuth2TokenResponse requestAccessToken(URI uri, HttpHeaders headers, Map<String, String> parameters) {
			requests.add(uri);
			return new OAuth2TokenResponse("token", 600L, null);
		}
	}
}
