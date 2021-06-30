package com.sap.cloud.security.client;

/**
 * Thrown to signal issues during a http client initialization.
 */
public class HttpClientException extends RuntimeException {
	/**
	 * Instantiates a new Service client exception.
	 *
	 * @param message
	 *            the message
	 */
	public HttpClientException(String message) {
		super(message);
	}
}
