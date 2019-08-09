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
import java.util.Optional;

import static com.sap.cloud.security.xsuaa.backend.TokenFlowsConstants.*;

public class OAuth2Server implements OAuth2TokenService {

	private RestTemplate restTemplate;

	public OAuth2Server(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}

	@Override
	public OAuth2AccessToken retrieveAccessTokenViaClientCredentialsGrant(URI tokenEndpointUri,
			ClientCredentials clientCredentials,
			Optional<Map<String, String>> optionalParameters) throws OAuth2ServerException {

		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS);

		optionalParameters.orElse(new HashMap<String, String>(0)).forEach(parameters::putIfAbsent);

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);

		// add query parameters to URI
		parameters.forEach(builder::queryParam);

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(clientCredentials);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		return requestAccessToken(requestUri, requestEntity);
	}

	@Deprecated
	@Override
	public OAuth2AccessToken retrieveAccessTokenViaUserTokenGrant(URI tokenEndpointUri,
			ClientCredentials clientCredentials, String token, Optional<Map<String, String>> optionalParameters)
			throws OAuth2ServerException {
		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_USER_TOKEN);
		parameters.put(PARAMETER_CLIENT_ID, clientCredentials.getClientId());

		optionalParameters.orElse(new HashMap<String, String>(0)).forEach(parameters::putIfAbsent);

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);

		// add query parameters to URI
		parameters.forEach(builder::queryParam);

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(token);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();
		return requestAccessToken(requestUri, requestEntity);
	}

	@Override
	public OAuth2AccessToken retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri,
			ClientCredentials clientCredentials,
			String refreshToken) throws OAuth2ServerException {

		Map<String, String> parameters = new HashMap<>();
		parameters.put(GRANT_TYPE, GRANT_TYPE_REFRESH_TOKEN);
		parameters.put(REFRESH_TOKEN, refreshToken);
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenEndpointUri);

		// add query parameters to URI
		parameters.forEach(builder::queryParam);

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(clientCredentials);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		return requestAccessToken(requestUri, requestEntity);
	}

	private OAuth2AccessToken requestAccessToken(URI requestUri, HttpEntity<Void> requestEntity)
			throws OAuth2ServerException {

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
		long expiresIn = Long.parseLong(String.valueOf(accessTokenMap.get(EXPIRES_IN)));
		String refreshToken = accessTokenMap.get(REFRESH_TOKEN);
		return new OAuth2AccessToken(accessToken, refreshToken, expiresIn);
	}

	/**
	 * Creates the set of HTTP headers with client-credentials basic authentication
	 * header.
	 *
	 * @return the HTTP headers.
	 */
	private static HttpHeaders createHeadersWithAuthorization(ClientCredentials credentials) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addBasicAuthHeader(headers, credentials);
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
	 * Adds the {@code  Authorization: Basic <credentials>} header to the set of
	 * headers.
	 *
	 * @param headers
	 *            - the set of headers to add the header to.
	 * @param credentials
	 *            - the client credentials used for authentication.
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
