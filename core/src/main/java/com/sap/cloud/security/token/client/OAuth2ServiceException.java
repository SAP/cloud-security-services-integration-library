package com.sap.cloud.security.token.client;

import java.io.IOException;

/**
 * Exception thrown to signal issues during communication with OAuth2 service.
 */
public class OAuth2ServiceException extends IOException {

	private static final long serialVersionUID = 1L;

	public OAuth2ServiceException(String message) {
		super(message);
	}
}