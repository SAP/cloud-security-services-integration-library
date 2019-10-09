package com.sap.cloud.security.xsuaa.http;

public enum MediaType {
	APPLICATION_JSON("application/json"),
	APPLICATION_FORM_URLENCODED("application/x-www-form-urlencoded");

	private final String value;

	MediaType(String value) {
		this.value = value;
	}

	public String value() {
		return value;
	}
}
