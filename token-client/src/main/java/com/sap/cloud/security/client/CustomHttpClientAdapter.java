/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import java.io.IOException;

/**
 * Adapter that wraps a user-provided {@link HttpRequestExecutor} to implement {@link SecurityHttpClient}.
 * This allows users to use any HTTP client library without needing library-specific adapter modules.
 *
 * <p>Example usage:
 * <pre>{@code
 * // User provides their own HTTP client executor
 * HttpRequestExecutor executor = (uri, method, headers, body) -> {
 *     // Use any HTTP client library here (Apache, OkHttp, etc.)
 *     return new HttpRequestExecutor.HttpResponse(statusCode, headers, body);
 * };
 *
 * // Wrap it in a SecurityHttpClient
 * SecurityHttpClient client = new CustomHttpClientAdapter(executor);
 *
 * // Use with token services
 * OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
 * }</pre>
 */
public class CustomHttpClientAdapter implements SecurityHttpClient {

	private final HttpRequestExecutor executor;

	/**
	 * Creates a new adapter with the given executor.
	 *
	 * @param executor the HTTP request executor implementation
	 */
	public CustomHttpClientAdapter(HttpRequestExecutor executor) {
		if (executor == null) {
			throw new IllegalArgumentException("HttpRequestExecutor cannot be null");
		}
		this.executor = executor;
	}

	@Override
	public SecurityHttpResponse execute(SecurityHttpRequest request) throws IOException {
		// Validate URI to prevent SSRF attacks
		validateUri(request.getUri());

		try {
			HttpRequestExecutor.HttpResponse response = executor.execute(
					request.getUri(),
					request.getMethod(),
					request.getHeaders(),
					request.getBody()
			);

			return new SecurityHttpResponse(
					response.getStatusCode(),
					response.getHeaders(),
					response.getBody()
			);
		} catch (HttpClientException e) {
			throw new IOException("HTTP request failed: " + e.getMessage(), e);
		}
	}

	/**
	 * Validates the URI to prevent SSRF attacks by ensuring it uses a safe scheme and has a valid host.
	 *
	 * @param uri the URI to validate
	 * @throws HttpClientException if the URI is invalid or uses an unsafe scheme
	 */
	private void validateUri(java.net.URI uri) throws HttpClientException {
		if (uri == null) {
			throw new HttpClientException("URI cannot be null");
		}

		String scheme = uri.getScheme();
		if (scheme == null || (!scheme.equalsIgnoreCase("https") && !scheme.equalsIgnoreCase("http"))) {
			throw new HttpClientException("Invalid URI scheme. Only HTTP/HTTPS are allowed: " + uri);
		}

		String host = uri.getHost();
		if (host == null || host.isEmpty()) {
			throw new HttpClientException("Invalid URI: missing host: " + uri);
		}
	}

	@Override
	public void close() throws IOException {
		// Custom executors are responsible for their own resource management
	}
}