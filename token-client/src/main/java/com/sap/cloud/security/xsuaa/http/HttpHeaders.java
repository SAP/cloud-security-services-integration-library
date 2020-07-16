package com.sap.cloud.security.xsuaa.http;

import java.util.*;
import java.util.stream.Collectors;

public class HttpHeaders {

	public static final String AUTHORIZATION = "Authorization";
	public static final String ACCEPT = "Accept";
	public static final String CONTENT_TYPE = "Content-Type";

	private final Set<HttpHeader> headers;

	public HttpHeaders(HttpHeader... headers) {
		this(Arrays.asList(headers));
	}

	public HttpHeaders(Collection<HttpHeader> headers) {
		this.headers = headers.stream().collect(Collectors.toSet());
	}

	public Set<HttpHeader> getHeaders() {
		return headers;
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
		return "HttpHeaders{" +
				"headers=" + headers +
				'}';
	}
}
