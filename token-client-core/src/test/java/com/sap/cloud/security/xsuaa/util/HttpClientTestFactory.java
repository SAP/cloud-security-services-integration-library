/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicStatusLine;
import org.mockito.Mockito;

import java.util.Arrays;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

public class HttpClientTestFactory {

	public static CloseableHttpResponse createHttpResponse(String responseAsJson, int statusCode) {
		Header[] headers = new Header[1];
		headers[0] = new BasicHeader("testHeader", "testValue");
		return createHttpResponse(responseAsJson, statusCode, headers);
	}

	public static CloseableHttpResponse createHttpResponse(String responseAsJson, int statusCode, Header[] headers) {
		CloseableHttpResponse response = Mockito.mock(CloseableHttpResponse.class);
		when(response.getStatusLine()).thenReturn(new BasicStatusLine(HttpVersion.HTTP_1_1, statusCode, null));
		when(response.getEntity()).thenReturn(new StringEntity(responseAsJson, ContentType.APPLICATION_JSON));
		when(response.getAllHeaders()).thenReturn(headers);
		Arrays.stream(headers).distinct().forEach(h -> {
			lenient().when(response.containsHeader(h.getName())).thenReturn(true);
			lenient().when(response.getFirstHeader(h.getName())).thenReturn(h);
		});
		return response;
	}

	public static CloseableHttpResponse createHttpResponse(String responseAsJson) {
		return createHttpResponse(responseAsJson, HttpStatus.SC_OK);
	}

	public static CloseableHttpResponse createHttpResponseWithHeaders(String responseAsJson, Header[] headers) {
		return createHttpResponse(responseAsJson, HttpStatus.SC_OK, headers);
	}
}
