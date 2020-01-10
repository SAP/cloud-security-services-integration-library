/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.xsa.security.container;

/**
 * @deprecated with version 2.4.0 in favor of the new SAP Java Container library.
 */
@Deprecated
 public class XSUserInfoException extends Exception {

	private static final long serialVersionUID = 1L;

	public XSUserInfoException(String message) {
		super(message);
	}

	public XSUserInfoException(String message, Throwable reason) {
		super(message, reason);
	}

}
