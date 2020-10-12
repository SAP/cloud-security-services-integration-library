package com.sap.cloud.security.token;

/**
 * Runtime exception during client id retrieval from token.
 */
public class InvalidTokenException extends RuntimeException {
	public InvalidTokenException(String message) {
		super(message);
	}
}
