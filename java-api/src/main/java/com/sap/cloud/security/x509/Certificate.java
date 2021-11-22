/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;

/**
 * Represents mTLS certificate.
 */
public interface Certificate {

	/**
	 * Gets base64 encoded certificate value.
	 *
	 * @return the certificate value
	 */
	String getCertificateValue();

	/**
	 * Gets certificate 'x5t' thumbprint which is a base64url-encoded SHA-1
	 * thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.8"/a>
	 *
	 * @return the thumbprint
	 * @throws CertificateEncodingException
	 *             if error occurs while encoding X509 certificate
	 * @throws NoSuchAlgorithmException
	 *             when a particular cryptographic algorithm is requested but is not
	 *             * available in the environment
	 */
	String getThumbprint() throws CertificateEncodingException, NoSuchAlgorithmException;

}
