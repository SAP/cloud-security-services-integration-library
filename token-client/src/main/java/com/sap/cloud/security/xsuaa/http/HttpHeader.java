package com.sap.cloud.security.xsuaa.http;

public class HttpHeader {

	private final String name;
	private final String value;

	public HttpHeader(String name, String value) {
		this.name = name;
		this.value = value;
	}

	public String getValue() {
		return value;
	}

	public String getName() {
		return name;
	}
}
