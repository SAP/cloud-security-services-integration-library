/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.util;

import com.sap.cloud.security.client.SecurityHttpResponse;

import java.util.HashMap;
import java.util.Map;

public class HttpClientTestFactory {

	public static SecurityHttpResponse createHttpResponse(String responseAsJson, int statusCode) {
		Map<String, String> headers = new HashMap<>();
		return new SecurityHttpResponse(statusCode, headers, responseAsJson);
	}

	public static SecurityHttpResponse createHttpResponse(String responseAsJson) {
		return createHttpResponse(responseAsJson, 200);
	}
}