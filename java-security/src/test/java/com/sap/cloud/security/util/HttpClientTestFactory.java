/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.util;

import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.mockito.Mockito;

import static org.mockito.Mockito.when;

public class HttpClientTestFactory {

	public static ClassicHttpResponse createHttpResponse(String responseAsJson, int statusCode) {
		ClassicHttpResponse response = Mockito.mock(ClassicHttpResponse.class);
		when(response.getCode()).thenReturn(statusCode);
		when(response.getEntity()).thenReturn(new StringEntity(responseAsJson, org.apache.hc.core5.http.ContentType.APPLICATION_JSON));
		return response;
	}

	public static ClassicHttpResponse createHttpResponse(String responseAsJson) {
		return createHttpResponse(responseAsJson, HttpStatus.SC_OK);
	}
}