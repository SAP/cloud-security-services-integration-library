/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.http;

import java.util.*;
import java.util.stream.Collectors;

public class HttpHeaders {

	public static final String AUTHORIZATION = "Authorization";
	public static final String ACCEPT = "Accept";
	public static final String CONTENT_TYPE = "Content-Type";
	public static final String X_ZID = "X-zid";
	public static final String X_ZONE_UUID = "x-zone_uuid";

	private final Set<HttpHeader> headers;

	public HttpHeaders(HttpHeader... headers) {
		this(Arrays.asList(headers));
	}

	public HttpHeaders(Collection<HttpHeader> headers) {
		this.headers = new HashSet<>(headers);
	}

	public Set<HttpHeader> getHeaders() {
		return headers;
	}

	public HttpHeaders withHeader(String headerName, String value) {
		this.headers.add(new HttpHeader(headerName, value));
		return this;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		HttpHeaders that = (HttpHeaders) o;
		return Objects.equals(headers, that.headers);
	}

	@Override
	public int hashCode() {
		return Objects.hash(headers);
	}

	@Override
	public String toString() {
		return "HttpHeaders: [ " +
				headers.stream().map(HttpHeader::toString)
						.collect(Collectors.joining(", "))
				+
				" ]";
	}
}
