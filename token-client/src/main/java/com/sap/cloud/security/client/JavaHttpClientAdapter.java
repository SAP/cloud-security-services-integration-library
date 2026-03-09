/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Adapter that wraps Java 11's HttpClient to implement SecurityHttpClient.
 */
class JavaHttpClientAdapter implements SecurityHttpClient {

	private final HttpClient httpClient;
	private final int socketTimeoutSeconds;

	JavaHttpClientAdapter(HttpClient httpClient, int socketTimeoutSeconds) {
		this.httpClient = httpClient;
		this.socketTimeoutSeconds = socketTimeoutSeconds;
	}

	@Override
	public SecurityHttpResponse execute(SecurityHttpRequest request) throws IOException {
		// Validate URI to prevent SSRF attacks
		validateUri(request.getUri());

		try {
			HttpRequest.Builder builder = HttpRequest.newBuilder()
					.uri(request.getUri())
					.timeout(Duration.ofSeconds(socketTimeoutSeconds));

			// Add headers
			request.getHeaders().forEach(builder::header);

			// Set method and body
			if (request.getBody() != null && request.getBody().length > 0) {
				builder.method(request.getMethod(),
						HttpRequest.BodyPublishers.ofByteArray(request.getBody()));
			} else {
				builder.method(request.getMethod(), HttpRequest.BodyPublishers.noBody());
			}

			HttpRequest httpRequest = builder.build();
			HttpResponse<String> response = httpClient.send(httpRequest,
					HttpResponse.BodyHandlers.ofString());

			// Convert headers
			Map<String, String> headers = new HashMap<>();
			response.headers().map().forEach((key, values) -> {
				if (!values.isEmpty()) {
					headers.put(key, values.get(0));
				}
			});

			return new SecurityHttpResponse(
					response.statusCode(),
					headers,
					response.body()
			);

		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("Request was interrupted", e);
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
	public void close() {
		// Java 11 HttpClient doesn't need explicit closing
	}
}
