package com.sap.cloud.security.xsuaa.backend;

/**
 * Exception thrown to signal issues during communication with OAuth2 service.
 */
public class OAuth2ServerException extends Exception {

	private static final long serialVersionUID = 1L;

	public OAuth2ServerException(String message) {
		super(message);
	}

	public OAuth2ServerException(String message, Throwable reason) {
		super(message, reason);
	}
}
