package com.sap.xs2.security.container;
import com.sap.xsa.security.container.XSUserInfoException;

public class UserInfoException extends XSUserInfoException {

	private static final long serialVersionUID = 1L;

	public UserInfoException(String message) {
		super(message);
	}

	public UserInfoException(String message, Throwable reason) {
		super(message, reason);
	}

}