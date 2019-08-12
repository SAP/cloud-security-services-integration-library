package com.sap.cloud.security.xsuaa.client;

/**
 * Exception thrown to signal issues during communication with OAuth2 service.
 */
public class OAuth2ServiceException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public OAuth2ServiceException(String message) {
		super(message);
	}

	public OAuth2ServiceException(String message, Throwable reason) {
		super(message, reason);
	}
}