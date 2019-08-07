package com.sap.cloud.security.xsuaa.backend;

import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class OAuth2Server {

	private RestTemplate restTemplate;

	public static final String ACCESS_TOKEN = "access_token";
	public static final String EXPIRES_IN = "expires_in";
	public static final String REFRESH_TOKEN = "refresh_token";

	public static final String RESPONSE_TYPE = "response_type"; // TODO: still required?
	public static final String RESPONSE_TYPE_TOKEN = "token"; // TODO: still required?

	public static final String GRANT_TYPE = "grant_type";
	public static final String GRANT_TYPE_USER_TOKEN = "user_token";
	public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
	public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";

	public static final String PARAMETER_CLIENT_ID = "client_id";

	public OAuth2Server(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}

	/**
	 * Requests access token from OAuth Server with client credentials, e.g. as documented here
	 * https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#token
	 *
	 * @return the returned OAuth2AccessToken.
	 * @throws OAuth2ServerException in case of an error during the http request.
	 */
	public OAuth2AccessToken retrieveAccessTokenViaClientCredentialsGrant(URI tokenEndpointUri, ClientCredentials credentials,
			Map<String, String> optionalParameters) throws OAuth2ServerException {
		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);

		optionalParameters.forEach((key, value) -> parameters.putIfAbsent(key, value));

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);

		// add query parameters to URI
		parameters.forEach((key, value) -> builder.queryParam(key, value));

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(credentials);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		return requestAccessToken(requestUri,requestEntity);
	}

	/**
	 * Requests user token from OAuth Server, e.g. as documented here
	 * https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#token
	 *
	 * @return the returned token info map.
	 * @throws OAuth2ServerException in case of an error during the http request.
	 */
	public OAuth2AccessToken retrieveAccessTokenViaUserTokenGrant(URI tokenEndpointUri, ClientCredentials clientCredentials, String token, Map<String, String> optionalParameters)
			throws OAuth2ServerException {
		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_USER_TOKEN);
		parameters.put(PARAMETER_CLIENT_ID, clientCredentials.getClientId());
		parameters.put(RESPONSE_TYPE, RESPONSE_TYPE_TOKEN); // required?

		optionalParameters.forEach((key, value) -> parameters.putIfAbsent(key, value));

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);

		// add query parameters to URI
		parameters.forEach((key, value) -> builder.queryParam(key, value));

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(token);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();
		return requestAccessToken(requestUri, requestEntity);
	}

	/**
	 * Requests access token from OAuth Server with refresh-token, e.g. as documented here
	 * https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#token
	 *
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServerException in case of an error during the http request.
	 */
	public OAuth2AccessToken retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri, ClientCredentials credentials,
			String refreshToken) throws OAuth2ServerException {

		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
		parameters.put(REFRESH_TOKEN, refreshToken);
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);

		// add query parameters to URI
		parameters.forEach((key, value) -> builder.queryParam(key, value));

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(credentials);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		return requestAccessToken(requestUri,requestEntity);
	}

	private OAuth2AccessToken requestAccessToken(URI requestUri, HttpEntity<Void> requestEntity)
			throws HttpClientErrorException, OAuth2ServerException {

		ResponseEntity<Map> responseEntity = null;
		try {
			responseEntity = restTemplate.postForEntity(requestUri, requestEntity, Map.class);
		} catch (HttpClientErrorException ex) {
			HttpStatus responseStatusCode = ex.getStatusCode();
			if (responseStatusCode == HttpStatus.UNAUTHORIZED) {
				throw new OAuth2ServerException(String.format(
						"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful. Client credentials invalid.",
						responseStatusCode));
			}
			if (!responseStatusCode.is2xxSuccessful()) {
				throw new OAuth2ServerException(String.format(
						"Error retrieving JWT token. Received status code %s. Call to XSUAA was not successful.",
						responseStatusCode));
			}
			throw new OAuth2ServerException(String.format(
					"Error retrieving JWT token. Call to XSUAA was not successful: %s",
					ex.getMessage()));
		}
		Map<String, String> accessTokenMap = responseEntity.getBody();

		String accessToken = accessTokenMap.get(ACCESS_TOKEN);
		long expires_in = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
		String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
		return new OAuth2AccessToken(accessToken, refreshToken, expires_in);
	}

	/**
	 * Creates a set of headers required for the token exchange with XSUAA.
	 *
	 * @return the set of headers.
	 */
	static private HttpHeaders createHeadersWithAuthorization(ClientCredentials credentials) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addBasicAuthHeader(headers, credentials);
		return headers;
	}

	/**
	 * Creates the set of HTTP headers necessary for the user token flow request.
	 *
	 * @return the HTTP headers.
	 */
	static private HttpHeaders createHeadersWithAuthorization(String token) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addAuthorizationBearerHeader(headers, token);
		return headers;
	}

	/** common utilities **/

	/**
	 * Adds the {@code  Accept: application/json} header to the set of headers.
	 *
	 * @param headers - the set of headers to add the header to.
	 */
	static void addAcceptHeader(HttpHeaders headers) {
		headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
	}

	/**
	 * Adds the {@code  Authorization: Basic <credentials>} header to the set of
	 * headers.
	 *
	 * @param headers     - the set of headers to add the header to.
	 * @param credentials - the client credentials used for authentication.
	 */
	static void addBasicAuthHeader(HttpHeaders headers, ClientCredentials credentials) {
		final String BASIC_AUTH_HEADER_FORMAT = "Basic %s";
		final String CREDENTIALS_FORMAT = "%s:%s";

		String credentialsString = String
				.format(CREDENTIALS_FORMAT, credentials.getClientId(), credentials.getClientSecret());
		String base64Creds = Base64.getEncoder().encodeToString(credentialsString.getBytes(StandardCharsets.UTF_8));
		headers.add(HttpHeaders.AUTHORIZATION, String.format(BASIC_AUTH_HEADER_FORMAT, base64Creds));
	}

	/**
	 * Adds the {@code  Authorization: Bearer <token>} header to the set of headers.
	 *
	 * @param headers - the set of headers to add the header to.
	 * @param token   - the token which should be part of the header.
	 */
	static void addAuthorizationBearerHeader(HttpHeaders headers, String token) {
		final String AUTHORIZATION_BEARER_TOKEN_FORMAT = "Bearer %s";
		headers.add(HttpHeaders.AUTHORIZATION, String.format(AUTHORIZATION_BEARER_TOKEN_FORMAT, token));
	}
}
