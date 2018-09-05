package com.sap.xsa.security.container;

public class XSUserInfoException extends Exception {

	private static final long serialVersionUID = 1L;

	public XSUserInfoException(String message) {
		super(message);
	}

	public XSUserInfoException(String message, Throwable reason) {
		super(message, reason);
	}

}
