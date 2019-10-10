package com.sap.cloud.security.xsuaa.http;

import java.util.List;

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
}
