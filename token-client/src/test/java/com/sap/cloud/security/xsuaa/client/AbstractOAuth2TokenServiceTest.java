package com.sap.cloud.security.xsuaa.client;

import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.tokenflows.CacheConfiguration;
import org.assertj.core.util.Maps;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class AbstractOAuth2TokenServiceTest {

	public static final URI TOKEN_ENDPOINT_URI = URI.create("http://test.token.endpoint/oauth/token");
	public static final String SUBDOMAIN = "subdomain";
	private final static TestCacheTicker TEST_CACHE_TICKER = new TestCacheTicker();
	private TestOAuth2TokenService cut;

	@Before
	public void setUp() {
		cut = new TestOAuth2TokenService(CacheConfiguration.DEFAULT);
		TEST_CACHE_TICKER.reset();
	}

	@Test
	public void retrieveAccessTokenViaClientCredentials_activeCache_responseNotNull() throws OAuth2ServiceException {
		OAuth2TokenResponse oAuth2TokenResponse = retrieveAccessTokenViaClientCredentials();
		assertThat(oAuth2TokenResponse).isNotNull();
	}

	@Test
	public void retrieveAccessTokenViaClientCredentials_noCache_responseNotNull() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(CacheConfiguration.CACHE_DISABLED);
		OAuth2TokenResponse oAuth2TokenResponse = retrieveAccessTokenViaClientCredentials();
		assertThat(oAuth2TokenResponse).isNotNull();
	}

	@Test
	public void retrieveAccessTokenViaRefreshToken_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaRefreshToken("refreshToken");
		retrieveAccessTokenViaRefreshToken("another refreshToken");
		retrieveAccessTokenViaRefreshToken("refreshToken");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void retrieveAccessTokenViaPasswordGrant_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaPasswordGrant("user1");
		retrieveAccessTokenViaPasswordGrant("user2");
		retrieveAccessTokenViaPasswordGrant("user1");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void retrieveAccessTokenViaClientCredentials_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaClientCredentials();
		retrieveAccessTokenViaClientCredentials(new ClientCredentials("other client id", "secret"), false);
		retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void retrieveAccessTokenViaJwtBearerTokenGrant_twoDistinctRequests_onlyTwoRequestCalls()
			throws OAuth2ServiceException {
		retrieveAccessTokenViaJwtBearerTokenGrant("token");
		retrieveAccessTokenViaJwtBearerTokenGrant("differentToken");
		retrieveAccessTokenViaJwtBearerTokenGrant("token");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_differentTokenEndpoint_requestsFreshToken() throws OAuth2ServiceException {
		retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI);
		retrieveAccessTokenViaPasswordGrant(URI.create("http://another.token.endpoint"));

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_differentSubdomain_requestsFreshToken() throws OAuth2ServiceException {
		retrieveAccessTokenViaRefreshToken("token", "subdomain1");
		retrieveAccessTokenViaRefreshToken("token", "subdomain2");

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_differentAdditionalParameters_requestsFreshToken() throws OAuth2ServiceException {
		retrieveAccessTokenViaJwtBearerTokenGrant("token", Maps.newHashMap("a", "b"));
		retrieveAccessTokenViaJwtBearerTokenGrant("token", Maps.newHashMap("1", "2"));

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
	}

	@Test
	public void requestAccessToken_sameAdditionalParameters_onlyOneRequestCall() throws OAuth2ServiceException {
		Map<String, String> parameters = Maps.newHashMap("a", "b");
		parameters.put("c", "d");
		Map<String, String> sameParametersDifferentOrder = Maps.newHashMap("c", "d");
		sameParametersDifferentOrder.put("a", "b");

		retrieveAccessTokenViaJwtBearerTokenGrant("token", parameters);
		retrieveAccessTokenViaJwtBearerTokenGrant("token", sameParametersDifferentOrder);

		assertThat(cut.tokenRequestCallCount).isOne();
	}

	@Test
	public void requestAccessToken_cacheGloballyDisabled_requestsFreshTokens() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(CacheConfiguration.CACHE_DISABLED);

		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse);
	}

	@Test
	public void clearCache_requestsFreshToken() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		cut.clearCache();
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse);
	}

	@Test
	public void requestAccessToken_cachedTokens_areTheSame() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(firstResponse).isSameAs(secondResponse);
	}

	@Test
	public void requestAccessToken_tokensAreInvalidatedAfterTime_requestsFreshToken() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials();
		TEST_CACHE_TICKER.advance(CacheConfiguration.DEFAULT.getExpireAfterWrite());
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials();

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse);
	}

	@Test
	public void requestAccessToken_cacheIsFull_requestsFreshToken() throws OAuth2ServiceException {
		cut = new TestOAuth2TokenService(CacheConfiguration.getInstance(Duration.ofMinutes(10), 1));
		OAuth2TokenResponse user1Response = retrieveAccessTokenViaPasswordGrant("user1");
		OAuth2TokenResponse user2Response = retrieveAccessTokenViaPasswordGrant("user2");
		OAuth2TokenResponse secondUser1Response = retrieveAccessTokenViaPasswordGrant("user1");

		assertThat(user1Response).isNotSameAs(secondUser1Response).isNotSameAs(user2Response);
		assertThat(cut.tokenRequestCallCount).isEqualTo(3);
	}

	@Test
	public void requestAccessToken_cacheDisabledForRequest_requestsFreshTokens() throws OAuth2ServiceException {
		OAuth2TokenResponse firstResponse = retrieveAccessTokenViaClientCredentials(clientCredentials(), false);
		OAuth2TokenResponse secondResponse = retrieveAccessTokenViaClientCredentials(clientCredentials(), true);
		OAuth2TokenResponse lastResponse = retrieveAccessTokenViaClientCredentials(clientCredentials(), false);

		assertThat(cut.tokenRequestCallCount).isEqualTo(2);
		assertThat(firstResponse).isNotSameAs(secondResponse);
		assertThat(firstResponse).isSameAs(lastResponse);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(String token) throws OAuth2ServiceException {
		return retrieveAccessTokenViaJwtBearerTokenGrant(token, null);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(String token,
			Map<String, String> optionalParameters) throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaJwtBearerTokenGrant(TOKEN_ENDPOINT_URI, clientCredentials(), token, null,
				optionalParameters);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaClientCredentials() throws OAuth2ServiceException {
		return retrieveAccessTokenViaClientCredentials(clientCredentials(), false);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaClientCredentials(ClientCredentials clientCredentials,
			boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaClientCredentialsGrant(TOKEN_ENDPOINT_URI, clientCredentials, SUBDOMAIN,
				null, disableCacheForRequest);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(String username) throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaPasswordGrant(TOKEN_ENDPOINT_URI, clientCredentials(), username, "password",
				SUBDOMAIN, null);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(URI tokenEndpointUri)
			throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaPasswordGrant(tokenEndpointUri, clientCredentials(), "username", "password",
				SUBDOMAIN, null);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(String refreshToken) throws OAuth2ServiceException {
		return retrieveAccessTokenViaRefreshToken(refreshToken, SUBDOMAIN);
	}

	private OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(String refreshToken, String subdomain)
			throws OAuth2ServiceException {
		return cut.retrieveAccessTokenViaRefreshToken(TOKEN_ENDPOINT_URI, clientCredentials(), refreshToken, subdomain);
	}

	private ClientCredentials clientCredentials() {
		return new ClientCredentials("clientId", "clientSecret");
	}

	private static class TestOAuth2TokenService extends AbstractOAuth2TokenService {

		private int tokenRequestCallCount = 0;

		public TestOAuth2TokenService(CacheConfiguration cacheConfiguration) {
			super(TEST_CACHE_TICKER, true, cacheConfiguration);
		}

		@Override
		protected OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
				Map<String, String> parameters) {
			tokenRequestCallCount++;
			return new OAuth2TokenResponse("", 1L, null);
		}

	}

	private static class TestCacheTicker implements Ticker {
		long elapsed = 0;

		@Override
		public long read() {
			return elapsed;
		}

		public void advance(Duration duration) {
			this.elapsed = elapsed + duration.toNanos();
		}

		public void reset() {
			elapsed = 0;
		}
	}
}