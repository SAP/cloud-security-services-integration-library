package com.sap.cloud.security.xsuaa.mtls;


/**
 * Thrown to signal issues during a http client initialization.
 */
public class ServiceClientException extends Exception {
	/**
	 * Instantiates a new Service client exception.
	 *
	 * @param message the message
	 */
	public ServiceClientException(String message) {
		super(message);
	}
}
