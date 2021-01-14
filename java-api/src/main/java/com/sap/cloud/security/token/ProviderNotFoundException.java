package com.sap.cloud.security.token;

/**
 * A dedicated runtime exception for missing implementations in {@link java.util.ServiceLoader} context
 */
public class ProviderNotFoundException extends RuntimeException {

	public ProviderNotFoundException() {
		super();
	}

	public ProviderNotFoundException(String message) {
		super(message);
	}
}
