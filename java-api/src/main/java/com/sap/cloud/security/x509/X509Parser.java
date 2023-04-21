/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

class X509Parser {
	public static final Logger LOGGER = LoggerFactory.getLogger(X509Parser.class);
	public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

	private X509Parser() {
	}

	/**
	 * Decodes X509 base64 encoded certificate into X509Certificate class
	 *
	 * @param encodedX509
	 *            base64 encoded X509 certificate
	 * @return Decoded X509Certificate
	 * @throws CertificateException
	 *             if String value of certificate cannot be parsed
	 */
	static X509Certificate parseCertificate(@Nonnull String encodedX509) throws CertificateException {
		String encodedPemX509 = formatBase64Cert(encodedX509);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		ByteArrayInputStream bytes = new ByteArrayInputStream(encodedPemX509.getBytes(StandardCharsets.UTF_8));
		return (X509Certificate) certFactory.generateCertificate(bytes);
	}

	/**
	 * Generates X509 thumbprint from provided certificate.
	 *
	 * @see <a href="https://tools.ietf.org/html/rfc8705#section-3.1"></a>
	 * @param x509Certificate
	 *            X509certificate object
	 * @return Thumbprint of X509 certificate
	 * @throws NoSuchAlgorithmException
	 *             when a particular cryptographic algorithm is requested but is not
	 *             available in the environment
	 * @throws CertificateEncodingException
	 *             is thrown if error occurs while encoding X509 certificate
	 */
	static String getCertificateThumbprint(X509Certificate x509Certificate)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] hashedX509 = sha256.digest(x509Certificate.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(hashedX509);
	}

	/**
	 * Formats the base64 encoded certificate to <a href=
	 * "https://docs.oracle.com/javase/8/docs/api/java/security/cert/CertificateFactory.html">JDK
	 * 1.8</a> required format.
	 *
	 * @param base64EncodedCert
	 *            the base64 encoded certificate
	 * @return formatted Base64 string surrounded by PEM labels
	 */
	static String formatBase64Cert(@Nonnull String base64EncodedCert) {
		Objects.requireNonNull(base64EncodedCert, "The provided Certificate can not be null");
		String cert = base64EncodedCert
				.replace("\\n", "")
				.replace(BEGIN_CERTIFICATE, BEGIN_CERTIFICATE + "\n")
				.replace(END_CERTIFICATE, "\n" + END_CERTIFICATE + "\n")
				.replaceAll("\\n$", "");
		return encodePemLabels(cert);
	}

	@Nonnull
	private static String encodePemLabels(String base64EncodedCert) {
		if (!base64EncodedCert.startsWith(BEGIN_CERTIFICATE)) {
			base64EncodedCert = BEGIN_CERTIFICATE + "\n" + base64EncodedCert;
		}
		if (!base64EncodedCert.endsWith(END_CERTIFICATE)) {
			base64EncodedCert = base64EncodedCert + "\n" + END_CERTIFICATE;
		}
		return base64EncodedCert;
	}

}
