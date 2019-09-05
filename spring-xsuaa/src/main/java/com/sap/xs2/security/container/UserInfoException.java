package com.sap.xs2.security.container;

import com.sap.xsa.security.container.XSUserInfoException;

/**
 * @deprecated will be removed with version 2.0
 */
@Deprecated
public class UserInfoException extends XSUserInfoException {

	private static final long serialVersionUID = 1L;

	public UserInfoException(String message) {
		super(message);
	}

	public UserInfoException(String message, Throwable reason) {
		super(message, reason);
	}

}