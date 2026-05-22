/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import java.net.URI;
import java.util.Map;

/**
 * Simple functional interface that allows users to provide their own HTTP client implementation.
 * This eliminates the need for adapter modules and supports any HTTP client library.
 *
 * <p>Example usage with Apache HttpClient 4.x:
 * <pre>{@code
 * CloseableHttpClient apacheClient = HttpClients.createDefault();
 * HttpRequestExecutor executor = (uri, method, headers, body) -> {
 *     HttpPost request = new HttpPost(uri);
 *     headers.forEach(request::addHeader);
 *     if (body != null) {
 *         request.setEntity(new ByteArrayEntity(body));
 *     }
 *     return apacheClient.execute(request, response -> {
 *         String responseBody = EntityUtils.toString(response.getEntity());
 *         Map<String, String> responseHeaders = new HashMap<>();
 *         for (Header header : response.getAllHeaders()) {
 *             responseHeaders.put(header.getName(), header.getValue());
 *         }
 *         return new HttpResponse(response.getStatusLine().getStatusCode(), responseHeaders, responseBody);
 *     });
 * };
 * }</pre>
 *
 * <p>Example usage with Apache HttpClient 5.x:
 * <pre>{@code
 * CloseableHttpClient client5 = HttpClients.createDefault();
 * HttpRequestExecutor executor = (uri, method, headers, body) -> {
 *     ClassicHttpRequest request = new HttpPost(uri);
 *     headers.forEach(request::addHeader);
 *     if (body != null) {
 *         request.setEntity(new ByteArrayEntity(body));
 *     }
 *     return client5.execute(request, response -> {
 *         String responseBody = EntityUtils.toString(response.getEntity());
 *         Map<String, String> responseHeaders = new HashMap<>();
 *         for (Header header : response.getAllHeaders()) {
 *             responseHeaders.put(header.getName(), header.getValue());
 *         }
 *         return new HttpResponse(response.getCode(), responseHeaders, responseBody);
 *     });
 * };
 * }</pre>
 *
 * <p>Example usage with OkHttp:
 * <pre>{@code
 * OkHttpClient okHttpClient = new OkHttpClient();
 * HttpRequestExecutor executor = (uri, method, headers, body) -> {
 *     Request.Builder builder = new Request.Builder().url(uri.toURL());
 *     headers.forEach(builder::addHeader);
 *     if (body != null) {
 *         builder.method(method, RequestBody.create(body));
 *     } else {
 *         builder.method(method, null);
 *     }
 *     try (Response response = okHttpClient.newCall(builder.build()).execute()) {
 *         Map<String, String> responseHeaders = new HashMap<>();
 *         response.headers().forEach(pair -> responseHeaders.put(pair.getFirst(), pair.getSecond()));
 *         return new HttpResponse(response.code(), responseHeaders, response.body().string());
 *     }
 * };
 * }</pre>
 */
@FunctionalInterface
public interface HttpRequestExecutor {

	/**
	 * Executes an HTTP request and returns the response.
	 *
	 * @param uri     the target URI
	 * @param method  the HTTP method (GET, POST, etc.)
	 * @param headers the request headers
	 * @param body    the request body (may be null)
	 * @return the HTTP response
	 * @throws HttpClientException if the request fails
	 */
	HttpResponse execute(URI uri, String method, Map<String, String> headers, byte[] body)
			throws HttpClientException;

	/**
	 * Simple container for HTTP response data.
	 */
	class HttpResponse {
		private final int statusCode;
		private final Map<String, String> headers;
		private final String body;

		public HttpResponse(int statusCode, Map<String, String> headers, String body) {
			this.statusCode = statusCode;
			this.headers = headers;
			this.body = body;
		}

		public int getStatusCode() {
			return statusCode;
		}

		public Map<String, String> getHeaders() {
			return headers;
		}

		public String getBody() {
			return body;
		}
	}
}