package com.sap.cloud.security.xsuaa.http;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class HttpHeadersFactory {

	private final Map<String, String> headers;

	public HttpHeadersFactory() {
		headers = new HashMap<>();
		headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON.value());
		headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED.value());
	}

	/**
	 * Adds the {@code  Authorization: Bearer <token>} header to the set of headers.
	 *
	 * @param token
	 *            - the token which should be part of the header.
	 * @return the builder instance.
	 */
	public HttpHeaders createWithAuthorizationBearerHeader(String token) {
		final String AUTHORIZATION_BEARER_TOKEN_FORMAT = "Bearer %s";
		headers.put(HttpHeaders.AUTHORIZATION, String.format(AUTHORIZATION_BEARER_TOKEN_FORMAT, token));
		return createFromHeaders();
	}

	/**
	 * Creates the set of HTTP headers with client-credentials basic authentication
	 * header.
	 *
	 * @return the HTTP headers.
	 */
	public HttpHeaders createWithoutAuthorizationHeader() {
		return createFromHeaders();
	}

	private HttpHeaders createFromHeaders() {
		List<HttpHeader> httpHeaders = this.headers.entrySet()
				.stream()
				.map(header -> new HttpHeader(header.getKey(), header.getValue()))
				.collect(Collectors.toList());
		return new HttpHeaders(httpHeaders);
	}

}
