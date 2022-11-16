/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.http;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class HttpHeadersFactory {

	private HttpHeadersFactory() {
	}

	/**
	 * Adds the {@code  Authorization: Bearer <token>} header to the set of headers.
	 *
	 * @param token
	 *            - the token which should be part of the header.
	 * @return the builder instance.
	 */
	public static HttpHeaders createWithAuthorizationBearerHeader(String token) {
		Map<String, String> headers = createDefaultHeaders();
		final String AUTHORIZATION_BEARER_TOKEN_FORMAT = "Bearer %s";
		headers.put(HttpHeaders.AUTHORIZATION, String.format(AUTHORIZATION_BEARER_TOKEN_FORMAT, token));
		return createFromHeaders(headers);
	}

	/**
	 * Creates the set of HTTP headers with client-credentials basic authentication
	 * header.
	 *
	 * @return the HTTP headers.
	 */
	public static HttpHeaders createWithoutAuthorizationHeader() {
		return createFromHeaders(createDefaultHeaders());
	}

	private static HttpHeaders createFromHeaders(Map<String, String> headers) {
		List<HttpHeader> httpHeaders = headers.entrySet()
				.stream()
				.map(header -> new HttpHeader(header.getKey(), header.getValue()))
				.collect(Collectors.toList());
		return new HttpHeaders(httpHeaders);
	}

	private static Map<String, String> createDefaultHeaders() {
		Map<String, String> headers = new HashMap<>();
		headers.put(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON.value());
		headers.put(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED.value());
		return headers;
	}

}
