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
 * {@link HttpRequestExecutor} implementation for Apache HttpClient 4.x.
 * This class provides backward compatibility for applications using Apache HttpClient 4.
 *
 * <p>This is also used internally by the library to support the deprecated constructors
 * that accept {@link CloseableHttpClient}.
 *
 * <p><strong>Deprecation Notice:</strong> This class is deprecated and will be removed in version 5.0.0.
 * Starting with version 4.0.0, the library uses Java 11's HttpClient as the default implementation.
 *
 * <p>Example usage:
 * <pre>{@code
 * CloseableHttpClient apacheClient = HttpClients.custom()
 *     .setMaxConnTotal(100)
 *     .setMaxConnPerRoute(20)
 *     .build();
 *
 * HttpRequestExecutor executor = new ApacheHttpClient4Executor(apacheClient);
 * SecurityHttpClient securityClient = new CustomHttpClientAdapter(executor);
 * DefaultOAuth2TokenService service = new DefaultOAuth2TokenService(securityClient);
 * }</pre>
 *
 * <p>For migration guidance, see the
 * <a href="https://github.com/SAP/cloud-security-xsuaa-integration/blob/main/token-client/APACHE_HTTPCLIENT_MIGRATION.md">
 * Apache HttpClient Migration Guide</a>.
 *
 * @since 4.0.0
 * @deprecated Since version 4.0.0. This class will be removed in version 5.0.0.
 *             Consider migrating to Java 11 HttpClient (default) or Apache HttpClient 5.
 * @see HttpRequestExecutor
 * @see CustomHttpClientAdapter
 */
@Deprecated(since = "4.0.0", forRemoval = true)
public class ApacheHttpClient4Executor implements HttpRequestExecutor {

	private final CloseableHttpClient httpClient;

	/**
	 * Creates a new executor for the given Apache HttpClient 4.x instance.
	 *
	 * @param httpClient the Apache HttpClient 4.x instance to use
	 * @throws IllegalArgumentException if httpClient is null
	 */
	public ApacheHttpClient4Executor(CloseableHttpClient httpClient) {
		if (httpClient == null) {
			throw new IllegalArgumentException("httpClient cannot be null");
		}
		this.httpClient = httpClient;
	}

	@Override
	public HttpResponse execute(URI uri, String method, Map<String, String> headers, byte[] body)
			throws HttpClientException {
		HttpUriRequest apacheRequest = createApacheRequest(uri, method, headers, body);

		try (CloseableHttpResponse response = httpClient.execute(apacheRequest)) {
			return convertResponse(response);
		} catch (IOException e) {
			throw new HttpClientException("HTTP request failed: " + e.getMessage(), e);
		}
	}

	private HttpUriRequest createApacheRequest(URI uri, String method, Map<String, String> headers, byte[] body) {
		HttpRequestBase apacheRequest;

		switch (method.toUpperCase()) {
			case "GET":
				apacheRequest = new HttpGet(uri);
				break;
			case "POST":
				apacheRequest = new HttpPost(uri);
				break;
			case "PUT":
				apacheRequest = new HttpPut(uri);
				break;
			case "DELETE":
				apacheRequest = new HttpDelete(uri);
				break;
			case "HEAD":
				apacheRequest = new HttpHead(uri);
				break;
			case "OPTIONS":
				apacheRequest = new HttpOptions(uri);
				break;
			case "PATCH":
				apacheRequest = new HttpPatch(uri);
				break;
			default:
				throw new IllegalArgumentException("Unsupported HTTP method: " + method);
		}

		// Add headers
		if (headers != null) {
			headers.forEach(apacheRequest::addHeader);
		}

		// Add body if present and request supports entity
		if (body != null && body.length > 0 && apacheRequest instanceof HttpEntityEnclosingRequestBase) {
			HttpEntityEnclosingRequestBase entityRequest = (HttpEntityEnclosingRequestBase) apacheRequest;
			entityRequest.setEntity(new ByteArrayEntity(body));
		}

		return apacheRequest;
	}

	private HttpResponse convertResponse(CloseableHttpResponse response) throws IOException {
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

		return new HttpResponse(statusCode, headers, body);
	}

	/**
	 * Returns the underlying Apache HttpClient instance.
	 * This can be used if you need to close the client or access its configuration.
	 *
	 * @return the Apache HttpClient 4.x instance
	 */
	public CloseableHttpClient getHttpClient() {
		return httpClient;
	}
}
