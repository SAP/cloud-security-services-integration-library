package com.sap.cloud.security.xsuaa.http;

import java.util.Objects;

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

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		final HttpHeader that = (HttpHeader) o;
		return Objects.equals(getName(), that.getName()) &&
				Objects.equals(getValue(), that.getValue());
	}

	@Override
	public int hashCode() {
		return Objects.hash(getName(), getValue());
	}
}
