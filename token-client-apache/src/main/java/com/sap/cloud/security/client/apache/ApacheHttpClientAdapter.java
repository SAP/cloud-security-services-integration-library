/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client.apache;

import com.sap.cloud.security.client.HttpClientException;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.Header;
import org.apache.http.client.methods.*;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;

/**
 * Adapter that wraps Apache HttpClient to implement SecurityHttpClient.
 * This allows existing code using Apache HttpClient to work with the new abstraction.
 */
public class ApacheHttpClientAdapter implements SecurityHttpClient {

	private final CloseableHttpClient httpClient;

	public ApacheHttpClientAdapter(CloseableHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public SecurityHttpResponse execute(SecurityHttpRequest request) throws IOException {
		HttpUriRequest httpRequest = createHttpRequest(request);

		return httpClient.execute(httpRequest, response -> {
			int statusCode = response.getStatusLine().getStatusCode();
			String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

			// Convert headers
			Map<String, String> headers = new HashMap<>();
			for (Header header : response.getAllHeaders()) {
				headers.put(header.getName(), header.getValue());
			}

			return new SecurityHttpResponse(statusCode, headers, body);
		});
	}

	private HttpUriRequest createHttpRequest (SecurityHttpRequest request) throws HttpClientException {
		HttpRequestBase httpRequest;

		switch (request.getMethod().toUpperCase()) {
			case "GET":
				httpRequest = new HttpGet(request.getUri());
				break;
			case "POST":
				HttpPost post = new HttpPost(request.getUri());
				if (request.getBody() != null) {
					post.setEntity(new ByteArrayEntity(request.getBody()));
				}
				httpRequest = post;
				break;
			case "PUT":
				HttpPut put = new HttpPut(request.getUri());
				if (request.getBody() != null) {
					put.setEntity(new ByteArrayEntity(request.getBody()));
				}
				httpRequest = put;
				break;
			case "DELETE":
				httpRequest = new HttpDelete(request.getUri());
				break;
			case "HEAD":
				httpRequest = new HttpHead(request.getUri());
				break;
			default:
				throw new HttpClientException("Unsupported HTTP method: " + request.getMethod());
		}

		// Add headers
		request.getHeaders().forEach(httpRequest::addHeader);

		return httpRequest;
	}

	@Override
	public void close() throws IOException {
		httpClient.close();
	}
}
