/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.util;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicHeader;
import org.mockito.Mockito;

import java.util.Arrays;

import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

public class HttpClientTestFactory {

	public static ClassicHttpResponse createHttpResponse(String responseAsJson, int statusCode) {
		Header[] headers = new Header[1];
		headers[0] = new BasicHeader("testHeader", "testValue");
		return createHttpResponse(responseAsJson, statusCode, headers);
	}

	public static ClassicHttpResponse createHttpResponse(String responseAsJson, int statusCode, Header[] headers) {
		ClassicHttpResponse response = Mockito.mock(ClassicHttpResponse.class);
		when(response.getCode()).thenReturn(statusCode);
		when(response.getEntity()).thenReturn(new StringEntity(responseAsJson, org.apache.hc.core5.http.ContentType.APPLICATION_JSON));
		when(response.getHeaders()).thenReturn(headers);
		Arrays.stream(headers).distinct().forEach(h -> {
			lenient().when(response.containsHeader(h.getName())).thenReturn(true);
			lenient().when(response.getFirstHeader(h.getName())).thenReturn(h);
		});
		return response;
	}

	public static ClassicHttpResponse createHttpResponse(String responseAsJson) {
		return createHttpResponse(responseAsJson, HttpStatus.SC_OK);
	}

	public static ClassicHttpResponse createHttpResponseWithHeaders(String responseAsJson, Header[] headers) {
		return createHttpResponse(responseAsJson, HttpStatus.SC_OK, headers);
	}
}
