/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import com.sap.cloud.security.client.SecurityHttpResponse;

import java.util.HashMap;
import java.util.Map;

public class HttpClientTestFactory {

	public static SecurityHttpResponse createHttpResponse(String responseAsJson, int statusCode) {
		Map<String, String> headers = new HashMap<>();
		headers.put("testHeader", "testValue");
		return createHttpResponse(responseAsJson, statusCode, headers);
	}

	public static SecurityHttpResponse createHttpResponse(String responseAsJson, int statusCode, Map<String, String> headers) {
		return new SecurityHttpResponse(statusCode, headers, responseAsJson);
	}

	public static SecurityHttpResponse createHttpResponse(String responseAsJson) {
		return createHttpResponse(responseAsJson, 200);
	}

	public static SecurityHttpResponse createHttpResponseWithHeaders(String responseAsJson, Map<String, String> headers) {
		return createHttpResponse(responseAsJson, 200, headers);
	}
}
