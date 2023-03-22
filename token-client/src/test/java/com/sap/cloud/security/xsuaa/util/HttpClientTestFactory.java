/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.mockito.Mockito;

import static org.mockito.Mockito.when;

public class HttpClientTestFactory {

	public static CloseableHttpResponse createHttpResponse(String responseAsJson, int statusCode) {
		CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);
		when(response.getCode()).thenReturn(statusCode);
		when(response.getEntity()).thenReturn(new StringEntity(responseAsJson, ContentType.APPLICATION_JSON));
		return response;
	}

	public static CloseableHttpResponse createHttpResponse(String responseAsJson) {
		return createHttpResponse(responseAsJson, HttpStatus.SC_OK);
	}
}
