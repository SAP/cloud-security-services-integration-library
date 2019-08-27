package com.sap.cloud.security.xsuaa.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.*;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS;

public class XsuaaOAuth2TokenService implements OAuth2TokenService {

	private RestOperations restOperations;
	private static Logger logger = LoggerFactory.getLogger(XsuaaOAuth2TokenService.class);

	public XsuaaOAuth2TokenService(@NonNull RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations is required");
		this.restOperations = restOperations;
	}

	@Override
	public OAuth2AccessToken retrieveAccessTokenViaClientCredentialsGrant(@NonNull URI tokenEndpointUri,
			@NonNull ClientCredentials clientCredentials,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		Assert.notNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assert.notNull(clientCredentials, "clientCredentials is required");

		Map<String, String> parameters = copy(optionalParameters);
		parameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);
		parameters.put(CLIENT_ID, clientCredentials.getId());
		parameters.put(CLIENT_SECRET, clientCredentials.getSecret());

		// build header
		HttpHeaders headers = createHeadersWithoutAuthorization();

		return requestAccessToken(replaceSubdomain(tokenEndpointUri, subdomain), headers, parameters);
	}

	@Override
	public OAuth2AccessToken retrieveAccessTokenViaUserTokenGrant(@NonNull URI tokenEndpointUri,
			@NonNull ClientCredentials clientCredentials, @NonNull String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException {
		Assert.notNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assert.notNull(clientCredentials, "clientCredentials is required");
		Assert.notNull(token, "token is required");

		Map<String, String> parameters = copy(optionalParameters);
		parameters.put(GRANT_TYPE, GRANT_TYPE_USER_TOKEN);
		parameters.put(PARAMETER_CLIENT_ID, clientCredentials.getId());

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(token);

		return requestAccessToken(replaceSubdomain(tokenEndpointUri, subdomain), headers, parameters);
	}

	@Override
	public OAuth2AccessToken retrieveAccessTokenViaRefreshToken(@NonNull URI tokenEndpointUri,
			@NonNull ClientCredentials clientCredentials,
			@NonNull String refreshToken, String subdomain) throws OAuth2ServiceException {
		Assert.notNull(tokenEndpointUri, "tokenEndpointUri is required");
		Assert.notNull(clientCredentials, "clientCredentials is required");
		Assert.notNull(refreshToken, "refreshToken is required");

		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
		parameters.put(REFRESH_TOKEN, refreshToken);
		parameters.put(CLIENT_ID, clientCredentials.getId());
		parameters.put(CLIENT_SECRET, clientCredentials.getSecret());

		// build header
		HttpHeaders headers = createHeadersWithoutAuthorization();

		return requestAccessToken(replaceSubdomain(tokenEndpointUri, subdomain), headers, parameters);
	}

	/**
	 * Utility method that replaces the subdomain of the URI with the given
	 * subdomain.
	 *
	 * @param uri
	 *            the URI to be replaced.
	 * @param subdomain
	 *            of the tenant.
	 * @return the URI with the replaced subdomain or the passed URI in case a
	 *         replacement was not possible.
	 */
	static URI replaceSubdomain(@NonNull URI uri, @Nullable String subdomain) {
		Assert.notNull(uri, "the uri parameter must not be null");
		if (StringUtils.hasText(subdomain) && uri.getHost().contains(".")) {
			UriBuilder builder = UriComponentsBuilder.newInstance().scheme(uri.getScheme())
					.host(subdomain + uri.getHost().substring(uri.getHost().indexOf("."))).port(uri.getPort())
					.path(uri.getPath());
			return uri.resolve(builder.build());
		}
		logger.warn("the subdomain of the URI '{}' is not replaced by subdomain '{}'", uri, subdomain);
		return uri;
	}

	private OAuth2AccessToken requestAccessToken(URI tokenEndpointUri, HttpHeaders headers,
			Map<String, String> parameters) {

		// Create URI
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);
		parameters.forEach(builder::queryParam);
		URI requestUri = builder.build().encode().toUri();

		// Create entity
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> responseEntity = null;
		try {
			responseEntity = restOperations.postForEntity(requestUri, requestEntity, Map.class);
		} catch (HttpClientErrorException ex) {
			HttpStatus responseStatusCode = ex.getStatusCode();
			if (responseStatusCode == HttpStatus.UNAUTHORIZED) {
				throw new OAuth2ServiceException(String.format(
						"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful. Client credentials invalid.",
						responseStatusCode));
			}
			if (!responseStatusCode.is2xxSuccessful()) {
				throw new OAuth2ServiceException(String.format(
						"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful.",
						responseStatusCode));
			}
			throw new OAuth2ServiceException(String.format(
					"Error retrieving JWT token. Call to XSUAA was not successful: %s",
					ex.getMessage()));
		}

		@SuppressWarnings("unchecked")
		Map<String, String> accessTokenMap = responseEntity.getBody();

		String accessToken = accessTokenMap.get(ACCESS_TOKEN);
		long expiresIn = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
		String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
		return new OAuth2AccessToken(accessToken, expiresIn, refreshToken);
	}

	/**
	 * Create a copy of the given map or an new empty map
	 * 
	 * @return a new Map that contains all entries of the optional map
	 */
	private static Map<String, String> copy(Map<String, String> map) {
		return map == null ? new HashMap<>() : new HashMap<>(map);
	}

	/**
	 * Creates the set of HTTP headers with client-credentials basic authentication
	 * header.
	 *
	 * @return the HTTP headers.
	 */
	private static HttpHeaders createHeadersWithoutAuthorization() {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		return headers;
	}

	/**
	 * Creates the set of HTTP headers with Authorization Bearer header.
	 *
	 * @return the HTTP headers.
	 */
	private static HttpHeaders createHeadersWithAuthorization(String token) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addAuthorizationBearerHeader(headers, token);
		return headers;
	}

	/** common utilities **/

	/**
	 * Adds the {@code  Accept: application/json} header to the set of headers.
	 *
	 * @param headers
	 *            - the set of headers to add the header to.
	 */
	static void addAcceptHeader(HttpHeaders headers) {
		headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
	}

	/**
	 * Adds the {@code  Authorization: Bearer <token>} header to the set of headers.
	 *
	 * @param headers
	 *            - the set of headers to add the header to.
	 * @param token
	 *            - the token which should be part of the header.
	 */
	static void addAuthorizationBearerHeader(HttpHeaders headers, String token) {
		final String AUTHORIZATION_BEARER_TOKEN_FORMAT = "Bearer %s";
		headers.add(HttpHeaders.AUTHORIZATION, String.format(AUTHORIZATION_BEARER_TOKEN_FORMAT, token));
	}
}
