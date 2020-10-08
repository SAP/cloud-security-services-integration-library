package com.sap.cloud.security.token;

/**
 * Runtime exception during client id retrieval from token.
 */
public class ClientIdRetrievalException extends RuntimeException {
	public ClientIdRetrievalException(String message) {
		super(message);
	}
}
