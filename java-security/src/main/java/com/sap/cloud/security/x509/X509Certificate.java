/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

/**
 * The X.509 certificate
 */
public class X509Certificate implements Certificate {

	private final String originalCertificate;
	private final java.security.cert.X509Certificate x509;
	private String thumbprint;

	private X509Certificate(java.security.cert.X509Certificate x509Certificate, String certificate) {
		this.x509 = x509Certificate;
		this.originalCertificate = certificate;
	}

	/**
	 * Creates a new instance of X.509 certificate.
	 *
	 * @param certificate
	 *            the certificate encoded in base64 or PEM format
	 * @return instance of X509certificate
	 * @throws CertificateException
	 *             if String value of certificate is invalid
	 */
	static X509Certificate newCertificate(@Nonnull String certificate) throws CertificateException {
		return new X509Certificate(X509Parser.parseCertificate(certificate), certificate);
	}

	// TODO private if possible
	@Override
	public String getCertificateValue() {
		return this.originalCertificate;
	}

	@Override
	public String getThumbprint() throws CertificateEncodingException, NoSuchAlgorithmException {
		if (thumbprint == null) {
			this.thumbprint = X509Parser.getCertificateThumbprint(x509);
		}
		return this.thumbprint;
	}

}
