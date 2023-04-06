/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.util;


import static org.mockito.Mockito.when;

import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicStatusLine;
import org.mockito.Mockito;

public class HttpClientTestFactory {

	public static CloseableHttpResponse createHttpResponse(String responseAsJson, int statusCode) {
		CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);
		when(response.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, statusCode, null));
		when(response.getEntity()).thenReturn(new StringEntity(responseAsJson, ContentType.APPLICATION_JSON));
		return response;
	}

	public static CloseableHttpResponse createHttpResponse(String responseAsJson) {
		return createHttpResponse(responseAsJson, HttpStatus.SC_OK);
	}
}