package com.sap.cloud.security.client;


/**
 * Thrown to signal issues during a http client initialization.
 */
public class ServiceClientException extends RuntimeException {
	/**
	 * Instantiates a new Service client exception.
	 *
	 * @param message the message
	 */
	public ServiceClientException(String message) {
		super(message);
	}
}
