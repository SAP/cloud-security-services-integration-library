package com.sap.cloud.security.xsuaa.client;

import java.io.IOException;

/**
 * Exception thrown to signal issues during communication with OAuth2 service.
 */
public class OAuth2ServiceException extends IOException {

	private static final long serialVersionUID = 1L;

	public OAuth2ServiceException(String message) {
		super(message);
	}

	public static OAuth2ServiceException createWithStatusCodeAndResponseBody(String message, int statusCode,
			String responseBodyAsString) {
		return new OAuth2ServiceException(
				String.format("%s. Received status code %s. Call to XSUAA was not successful: %s",
						message, statusCode, responseBodyAsString));
	}
}