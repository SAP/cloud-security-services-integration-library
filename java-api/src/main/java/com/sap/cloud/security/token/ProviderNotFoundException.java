package com.sap.cloud.security.token;

public class ProviderNotFoundException extends RuntimeException {

	public ProviderNotFoundException() {
		super();
	}

	public ProviderNotFoundException(String message) {
		super(message);
	}
}
