package com.sap.cloud.security.token;

/**
 * Runtime exception during token validation.
 */
public class InvalidTokenException extends RuntimeException {
	public InvalidTokenException(String message) {
		super(message);
	}
}
