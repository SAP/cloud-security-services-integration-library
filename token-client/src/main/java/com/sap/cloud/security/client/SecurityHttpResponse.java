/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents an HTTP response with status code, headers, and body.
 */
public class SecurityHttpResponse {

	private final int statusCode;
	private final Map<String, String> headers;
	private final String body;

	public SecurityHttpResponse(int statusCode, Map<String, String> headers, String body) {
		this.statusCode = statusCode;
		this.headers = new HashMap<>(headers);
		this.body = body;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public Map<String, String> getHeaders() {
		return new HashMap<>(headers);
	}

	public String getHeader(String name) {
		return headers.get(name);
	}

	public String getBody() {
		return body;
	}
}
