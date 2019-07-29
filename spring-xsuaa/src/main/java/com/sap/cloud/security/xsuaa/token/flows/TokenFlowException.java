package com.sap.cloud.security.xsuaa.token.flows;

/**
 * Exception thrown to signal issues during a token flow execution.
 */
public class TokenFlowException extends Exception {
	private static final long serialVersionUID = 1452898292676860358L;

	/**
	 * Creates a new exception instances.
	 */
	public TokenFlowException() {
		super();
	}

	/**
	 * Creates a new exception instances.
	 * 
	 * @param message
	 *            - the error message.
	 * @param cause
	 *            - the error cause.
	 * @param enableSuppression
	 *            - flag to enable or disable suppression.
	 * @param writableStackTrace
	 *            - flag to enable or disable writable stack trace.
	 */
	public TokenFlowException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	/**
	 * Creates a new exception instances.
	 * 
	 * @param message
	 *            - the error message.
	 * @param cause
	 *            - the error cause.
	 */
	public TokenFlowException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 * Creates a new exception instances.
	 * 
	 * @param message
	 *            - the error message.
	 */
	public TokenFlowException(String message) {
		super(message);
	}

	/**
	 * Creates a new exception instances.
	 * 
	 * @param cause
	 *            - the error cause.
	 */
	public TokenFlowException(Throwable cause) {
		super(cause);
	}
}
