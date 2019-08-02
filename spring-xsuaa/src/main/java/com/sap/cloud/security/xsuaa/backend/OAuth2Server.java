package com.sap.cloud.security.xsuaa.backend;

import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public class OAuth2Server {

	private RestTemplate restTemplate;

	private OAuth2ServerEndpointsProvider endpointsProvider;

	public OAuth2Server(RestTemplate restTemplate, OAuth2ServerEndpointsProvider endpointsProvider) {
		this.restTemplate = restTemplate;
		this.endpointsProvider = endpointsProvider;
	}

	/**
	 * Requests client-credentials token from OAuth Server, e.g. as documented here
	 * https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#token
	 *
	 * @return the returned token info map.
	 *
	 * @throws OAuth2ServerException in case of an error during the http request.
	 */
	public Map requestToken(Map<String, String> parameters, String clientId,
			String clientSecret) throws OAuth2ServerException {

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endpointsProvider.getTokenEndpoint());

		// add query parameters to URI
		parameters.forEach((key, value) -> builder.queryParam(key, value));

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(clientId, clientSecret);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		return requestToken(requestEntity, requestUri);
	}

	/**
	 * Requests user token from OAuth Server, e.g. as documented here
	 * https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#token
	 *
	 * @return the returned token info map.
	 *
	 * @throws OAuth2ServerException in case of an error during the http request.
	 */
	public Map requestToken(Map<String, String> parameters, String token) throws OAuth2ServerException {

		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(endpointsProvider.getTokenEndpoint());

		// add query parameters to URI
		parameters.forEach((key, value) -> builder.queryParam(key, value));

		// build header
		HttpHeaders headers = createHeadersWithAuthorization(token);
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		URI requestUri = builder.build().encode().toUri();

		return requestToken(requestEntity, requestUri);
	}

	private Map requestToken(HttpEntity<Void> requestEntity, URI requestUri)
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
		}
		return responseEntity.getBody();
	}

	public OAuth2ServerEndpointsProvider getEndpointsProvider() {
		return endpointsProvider;
	}

	/**
	 * Creates a set of headers required for the token exchange with XSUAA.
	 *
	 * @return the set of headers.
	 */
	static private HttpHeaders createHeadersWithAuthorization(String clientId, String clientSecret) {
		HttpHeaders headers = new HttpHeaders();
		addAcceptHeader(headers);
		addBasicAuthHeader(headers, clientId, clientSecret);
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
	 * @param clientId
	 *            - the client ID used for authentication.
	 * @param clientSecret
	 *            - the client secret used for authentication.
	 */
	static void addBasicAuthHeader(HttpHeaders headers, String clientId, String clientSecret) {
		final String BASIC_AUTH_HEADER_FORMAT = "Basic %s";
		final String CREDENTIALS_FORMAT = "%s:%s";

		String credentials = String.format(CREDENTIALS_FORMAT, clientId, clientSecret);
		String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
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
