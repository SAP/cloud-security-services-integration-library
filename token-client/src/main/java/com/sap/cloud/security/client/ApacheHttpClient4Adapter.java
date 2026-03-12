/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Adapter for Apache HttpClient 4.x to work with the SecurityHttpClient interface.
 * This class provides backward compatibility for applications using Apache HttpClient 4.
 *
 * <p><strong>Deprecation Notice:</strong> This class is deprecated and will be removed in version 5.0.0.
 * Starting with version 4.0.0, the library uses Java 11's HttpClient as the default implementation.
 * If you need custom HTTP client features, implement the {@link HttpRequestExecutor} interface instead.
 *
 * <p>Example usage:
 * <pre>{@code
 * CloseableHttpClient apacheClient = HttpClients.createDefault();
 * SecurityHttpClient securityClient = new ApacheHttpClient4Adapter(apacheClient);
 * DefaultOAuth2TokenService service = new DefaultOAuth2TokenService(securityClient);
 * }</pre>
 *
 * <p>For migration guidance, see the
 * <a href="https://github.com/SAP/cloud-security-xsuaa-integration/blob/main/token-client/APACHE_HTTPCLIENT_MIGRATION.md">
 * Apache HttpClient Migration Guide</a>.
 *
 * @since 4.0.0
 * @deprecated Since version 4.0.0. This class will be removed in version 5.0.0.
 *             Use {@link CustomHttpClientAdapter} with {@link HttpRequestExecutor} instead.
 * @see HttpRequestExecutor
 * @see CustomHttpClientAdapter
 */
@Deprecated(since = "4.0.0", forRemoval = true)
public class ApacheHttpClient4Adapter implements SecurityHttpClient {

	private final CloseableHttpClient httpClient;

	/**
	 * Creates a new adapter for the given Apache HttpClient 4.x instance.
	 *
	 * @param httpClient the Apache HttpClient 4.x instance to wrap
	 */
	public ApacheHttpClient4Adapter(CloseableHttpClient httpClient) {
		if (httpClient == null) {
			throw new IllegalArgumentException("httpClient cannot be null");
		}
		this.httpClient = httpClient;
	}

	@Override
	public SecurityHttpResponse execute(SecurityHttpRequest request) throws IOException {
		// Validate URI to prevent SSRF attacks
		validateUri(request.getUri());

		// Convert SecurityHttpRequest to Apache request
		HttpUriRequest apacheRequest = createApacheRequest(request);

		// Execute and convert response
		try (CloseableHttpResponse response = httpClient.execute(apacheRequest)) {
			return convertResponse(response);
		}
	}

	private HttpUriRequest createApacheRequest(SecurityHttpRequest request) {
		HttpRequestBase apacheRequest;

		// Create appropriate request type based on HTTP method
		switch (request.getMethod().toUpperCase()) {
			case "GET":
				apacheRequest = new HttpGet(request.getUri());
				break;
			case "POST":
				apacheRequest = new HttpPost(request.getUri());
				break;
			case "PUT":
				apacheRequest = new HttpPut(request.getUri());
				break;
			case "DELETE":
				apacheRequest = new HttpDelete(request.getUri());
				break;
			case "HEAD":
				apacheRequest = new HttpHead(request.getUri());
				break;
			case "OPTIONS":
				apacheRequest = new HttpOptions(request.getUri());
				break;
			case "PATCH":
				apacheRequest = new HttpPatch(request.getUri());
				break;
			default:
				throw new IllegalArgumentException("Unsupported HTTP method: " + request.getMethod());
		}

		// Add headers
		request.getHeaders().forEach(apacheRequest::addHeader);

		// Add body if present and request supports entity
		if (request.getBody() != null && request.getBody().length > 0 && apacheRequest instanceof HttpEntityEnclosingRequestBase) {
			HttpEntityEnclosingRequestBase entityRequest = (HttpEntityEnclosingRequestBase) apacheRequest;
			entityRequest.setEntity(new ByteArrayEntity(request.getBody()));
		}

		return apacheRequest;
	}

	private SecurityHttpResponse convertResponse(CloseableHttpResponse response) throws IOException {
		int statusCode = response.getStatusLine().getStatusCode();

		// Convert headers
		Map<String, String> headers = new HashMap<>();
		for (Header header : response.getAllHeaders()) {
			headers.put(header.getName(), header.getValue());
		}

		// Extract body
		String body = "";
		HttpEntity entity = response.getEntity();
		if (entity != null) {
			body = EntityUtils.toString(entity);
		}

		return new SecurityHttpResponse(statusCode, headers, body);
	}

	/**
	 * Validates the URI to prevent SSRF attacks by ensuring it uses a safe scheme and has a valid host.
	 *
	 * @param uri the URI to validate
	 * @throws HttpClientException if the URI is invalid or uses an unsafe scheme
	 */
	private void validateUri(URI uri) throws HttpClientException {
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
		httpClient.close();
	}
}
