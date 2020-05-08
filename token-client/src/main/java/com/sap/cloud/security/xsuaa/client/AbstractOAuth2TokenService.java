package com.sap.cloud.security.xsuaa.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.http.HttpHeaders;
import com.sap.cloud.security.xsuaa.http.HttpHeadersFactory;
import com.sap.cloud.security.xsuaa.tokenflows.CacheConfiguration;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import com.sap.cloud.security.xsuaa.util.UriUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;
import java.util.Objects;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;

@java.lang.SuppressWarnings("squid:S1192")
public abstract class AbstractOAuth2TokenService implements OAuth2TokenService, Cacheable {

	private Cache<CacheKey, OAuth2TokenResponse> responseCache;

	public AbstractOAuth2TokenService() {
	}

	@Override
	public void clearCache() {
		getOrCreateResponseCache().invalidateAll();
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_CLIENT_CREDENTIALS)
				.withClientCredentials(clientCredentials)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpointUri, parameters, headers, subdomain);
	}

	private OAuth2TokenResponse getOAuth2TokenResponse(@Nonnull URI tokenEndpointUri, Map<String, String> parameters, HttpHeaders headers, @Nullable String subdomain) throws OAuth2ServiceException {
		URI tokenEndpointUriWithSubdomainReplaced = UriUtil.replaceSubdomain(tokenEndpointUri, subdomain);
		if (isCacheEnabled()) {
			CacheKey cacheKey = new CacheKey(tokenEndpointUriWithSubdomainReplaced, headers, parameters);
			OAuth2TokenResponse oAuth2TokenResponse = getOrCreateResponseCache().getIfPresent(cacheKey);
			if (oAuth2TokenResponse == null) {
				getOrCreateResponseCache()
						.put(cacheKey, requestAccessToken(tokenEndpointUriWithSubdomainReplaced, headers, parameters));
			}
			return getOrCreateResponseCache().getIfPresent(cacheKey);
		}
		return requestAccessToken(tokenEndpointUriWithSubdomainReplaced, headers, parameters);
	}

	private boolean isCacheEnabled() {
		return !CacheConfiguration.NO_CACHE.equals(getCacheConfiguration());
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaUserTokenGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials, @Nonnull String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");
		assertNotNull(token, "token is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_USER_TOKEN)
				.withClientId(clientCredentials.getId())
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithAuthorizationBearerHeader(token);

		return getOAuth2TokenResponse(tokenEndpointUri, parameters, headers, subdomain);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientCredentials clientCredentials,
			@Nonnull String refreshToken, String subdomain) throws OAuth2ServiceException {
		assertNotNull(tokenEndpointUri, "tokenEndpointUri is required");
		assertNotNull(clientCredentials, "clientCredentials is required");
		assertNotNull(refreshToken, "refreshToken is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_REFRESH_TOKEN)
				.withRefreshToken(refreshToken)
				.withClientCredentials(clientCredentials)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpointUri, parameters, headers, subdomain);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(@Nonnull URI tokenEndpoint,
			@Nonnull ClientCredentials clientCredentials, @Nonnull String username, @Nonnull String password,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		assertNotNull(clientCredentials, "clientCredentials are required");
		assertNotNull(username, "username is required");
		assertNotNull(password, "password is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_PASSWORD)
				.withUsername(username)
				.withPassword(password)
				.withClientCredentials(clientCredentials)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpoint, parameters, headers, subdomain);
	}

	@Override
	public OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpoint,
			ClientCredentials clientCredentials, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {
		assertNotNull(tokenEndpoint, "tokenEndpoint is required");
		assertNotNull(clientCredentials, "clientCredentials are required");
		assertNotNull(token, "token is required");

		Map<String, String> parameters = new RequestParameterBuilder()
				.withGrantType(GRANT_TYPE_JWT_BEARER)
				.withClientCredentials(clientCredentials)
				.withToken(token)
				.withOptionalParameters(optionalParameters)
				.buildAsMap();

		HttpHeaders headers = HttpHeadersFactory.createWithoutAuthorizationHeader();

		return getOAuth2TokenResponse(tokenEndpoint, parameters, headers, subdomain);
	}

	/**
	 * Implements the HTTP client specific logic to perform an HTTP request and
	 * handle the response.
	 *
	 * @param tokenEndpointUri
	 *            the URI of the token endpoint the request must be sent to.
	 * @param headers
	 *            the HTTP headers that must be sent with the request.
	 * @param parameters
	 *            a map of request parameters that must be sent with the request.
	 * @return the token response.
	 * @throws OAuth2ServiceException
	 *             when the request ot the token endpoint fails or returns an error
	 *             code.
	 */
	protected abstract OAuth2TokenResponse requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) throws OAuth2ServiceException;


	@NonNull
	private Cache<CacheKey, OAuth2TokenResponse> getOrCreateResponseCache() {
		if (responseCache == null) {
			responseCache = Caffeine.newBuilder()
					.maximumSize(getCacheConfiguration().getCacheSize())
					.expireAfterWrite(getCacheConfiguration().getExpireAfterWrite())
					.build();
		}
		return responseCache;
	}

	private class CacheKey {

		private final URI tokenEndpointUri;
		private final HttpHeaders headers;
		private final Map<String, String> parameters;

		public CacheKey(URI tokenEndpointUri, HttpHeaders headers, Map<String, String> parameters) {
			this.tokenEndpointUri = tokenEndpointUri;
			this.headers = headers;
			this.parameters = parameters;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) return true;
			if (o == null || getClass() != o.getClass()) return false;
			CacheKey cacheKey = (CacheKey) o;
			return Objects.equals(tokenEndpointUri, cacheKey.tokenEndpointUri) &&
					Objects.equals(headers, cacheKey.headers) &&
					Objects.equals(parameters, cacheKey.parameters);
		}

		@Override
		public int hashCode() {
			return Objects.hash(tokenEndpointUri, headers, parameters);
		}
	}

}
