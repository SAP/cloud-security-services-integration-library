/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

/**
 * Runtime exception during certificate parsing and validation.
 */
public class InvalidCertificateException extends RuntimeException {
	public InvalidCertificateException(String message, Exception e) {
		super(message, e);
	}

	public InvalidCertificateException(String message) {
		super(message);
	}
}
