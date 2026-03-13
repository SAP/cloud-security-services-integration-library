/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import java.io.IOException;

import javax.annotation.Nullable;

/**
 * Adapter that wraps a user-provided {@link HttpRequestExecutor} to implement {@link SecurityHttpClient}.
 * This allows users to use any HTTP client library without needing library-specific adapter modules.
 *
 * <p>Example usage:
 * <pre>{@code
 * // User provides their own HTTP client executor
 * CloseableHttpClient apacheClient = HttpClients.createDefault();
 * HttpRequestExecutor executor = (uri, method, headers, body) -> {
 *     // Use any HTTP client library here (Apache, OkHttp, etc.)
 *     return new HttpRequestExecutor.HttpResponse(statusCode, headers, body);
 * };
 *
 * // Wrap it in a SecurityHttpClient with close handler
 * SecurityHttpClient client = new CustomHttpClientAdapter(executor, apacheClient::close);
 *
 * // Use with token services
 * OAuth2TokenService tokenService = new DefaultOAuth2TokenService(client);
 * }</pre>
 */
public class CustomHttpClientAdapter implements SecurityHttpClient {

	private final HttpRequestExecutor executor;
	@Nullable
	private final CloseHandler closeHandler;

	/**
	 * Functional interface for resource cleanup.
	 * Used to close underlying HTTP client resources when the adapter is closed.
	 */
	@FunctionalInterface
	public interface CloseHandler {
		/**
		 * Called when the adapter is closed.
		 *
		 * @throws IOException if closing fails
		 */
		void close() throws IOException;
	}

	/**
	 * Creates a new adapter with the given executor.
	 * The adapter's {@link #close()} method will be a no-op.
	 *
	 * @param executor the HTTP request executor implementation
	 */
	public CustomHttpClientAdapter(HttpRequestExecutor executor) {
		this(executor, null);
	}

	/**
	 * Creates a new adapter with the given executor and close handler.
	 *
	 * <p>Example usage:
	 * <pre>{@code
	 * CloseableHttpClient apacheClient = HttpClients.createDefault();
	 * HttpRequestExecutor executor = (uri, method, headers, body) -> { ... };
	 * SecurityHttpClient client = new CustomHttpClientAdapter(executor, apacheClient::close);
	 * }</pre>
	 *
	 * @param executor     the HTTP request executor implementation
	 * @param closeHandler called when {@link #close()} is invoked, may be null
	 */
	public CustomHttpClientAdapter(HttpRequestExecutor executor, @Nullable CloseHandler closeHandler) {
		if (executor == null) {
			throw new IllegalArgumentException("HttpRequestExecutor cannot be null");
		}
		this.executor = executor;
		this.closeHandler = closeHandler;
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
		if (closeHandler != null) {
			closeHandler.close();
		}
	}
}