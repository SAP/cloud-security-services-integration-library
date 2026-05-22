/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents an HTTP request with method, URI, headers, and optional body.
 */
public class SecurityHttpRequest {

	private final String method;
	private final URI uri;
	private final Map<String, String> headers;
	private final byte[] body;

	private SecurityHttpRequest(Builder builder) {
		this.method = builder.method;
		this.uri = builder.uri;
		this.headers = new HashMap<>(builder.headers);
		this.body = builder.body;
	}

	public String getMethod() {
		return method;
	}

	public URI getUri() {
		return uri;
	}

	public Map<String, String> getHeaders() {
		return new HashMap<>(headers);
	}

	public byte[] getBody() {
		return body;
	}

	public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {
		private String method = "GET";
		private URI uri;
		private Map<String, String> headers = new HashMap<>();
		private byte[] body;

		public Builder method(String method) {
			this.method = method;
			return this;
		}

		public Builder uri(URI uri) {
			this.uri = uri;
			return this;
		}

		public Builder header(String name, String value) {
			this.headers.put(name, value);
			return this;
		}

		public Builder headers(Map<String, String> headers) {
			this.headers.putAll(headers);
			return this;
		}

		public Builder body(byte[] body) {
			this.body = body;
			return this;
		}

		public SecurityHttpRequest build() {
			if (uri == null) {
				throw new IllegalStateException("URI is required");
			}
			return new SecurityHttpRequest(this);
		}
	}
}
