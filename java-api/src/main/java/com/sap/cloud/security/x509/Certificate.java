/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;


/**
 * Represents mTLS certificate.
 */
public interface Certificate {

	/**
	 * Gets certificate 'x5t' thumbprint which is a base64url-encoded SHA-1
	 * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
	 *
	 * @see <a href=
	 *      "https://datatracker.ietf.org/doc/html/rfc7517#section-4.8">x5t</a>
	 *
	 * @return the thumbprint
	 * @throws InvalidCertificateException
	 *             if error occurs while encoding X509 certificate
	 *             or when a particular cryptographic algorithm is not supported
	 */
	String getThumbprint() throws InvalidCertificateException;

}
