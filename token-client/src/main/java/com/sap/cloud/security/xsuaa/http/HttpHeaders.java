package com.sap.cloud.security.xsuaa.http;

import java.util.List;
import java.util.Objects;

public class HttpHeaders {

	public static final String AUTHORIZATION = "Authorization";
	public static final String ACCEPT = "Accept";
	public static final String CONTENT_TYPE = "Content-Type";

	private final List<HttpHeader> headers;

	public HttpHeaders(List<HttpHeader> headers) {
		this.headers = headers;
	}

	public List<HttpHeader> getHeaders() {
		return headers;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		HttpHeaders that = (HttpHeaders) o;
		return Objects.equals(headers, that.headers);
	}

	@Override
	public int hashCode() {
		return Objects.hash(headers);
	}
}
