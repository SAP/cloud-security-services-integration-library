/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.security.auth.x500.X500Principal;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * The X.509 certificate
 */
public class X509Certificate implements Certificate {

	private static final Logger LOGGER = LoggerFactory.getLogger(X509Certificate.class);

	private final java.security.cert.X509Certificate x509;
	private String thumbprint;
	private final String pem;

	private X509Certificate(java.security.cert.X509Certificate x509Certificate, String pem) {
		this.x509 = x509Certificate;
		this.pem = pem;
	}

	/**
	 * Creates a new instance of X.509 certificate.
	 *
	 * @param pemOrXfcc
	 * 		the certificate encoded in base64 or PEM format
	 * @return instance of X509certificate
	 */
	@Nullable
	public static X509Certificate newCertificate(String pemOrXfcc) {
		X509Certificate result = newCertificateFromPEM(pemOrXfcc);
		if (result == null) {
			result = newCertificateFromXFCC(pemOrXfcc);
		}
		return result;
	}

	/**
	 * Creates a new instance of X.509 certificate.
	 *
	 * @param pem
	 * 		the certificate encoded in base64 or PEM format
	 * @return instance of X509certificate
	 */
	@Nullable
	public static X509Certificate newCertificateFromPEM(String pem) {
		if (pem != null && !pem.isEmpty()) {
			try {
				return new X509Certificate(X509Parser.parseCertificate(pem), pem);
			} catch (CertificateException e) {
				LOGGER.debug("Could not parse the certificate string", e);
			}
		}
		return null;
	}

	/**
	 * Creates a new instance of X.509 certificate.
	 *
	 * @param headerValue
	 * 		the certificate encoded in base64 or PEM format
	 * @return instance of X509certificate
	 */
	@Nullable
	public static X509Certificate newCertificateFromXFCC(String headerValue) {
		Optional<String> urlEncodedCert = Optional.empty();

		if (headerValue != null) {
			urlEncodedCert = Stream.of(headerValue.split(",")).flatMap(s -> Stream.of(s.split(";")))
						.filter(s -> s.split("=")[0].equalsIgnoreCase("Cert"))
						.map(s -> {
							var a = s.split("=");
							if (a.length != 2) {
								return "";
							}
							s = a[1];
							if (s.startsWith("\"") && s.endsWith("\"")) {
								s = s.substring(1, s.length() - 1).replace("\\\"", "\"");
							}
							return s;
						})
						.reduce((first, second) -> second);
		}

		if (urlEncodedCert.isPresent()) {
			String cert = URLDecoder.decode(urlEncodedCert.get(), StandardCharsets.UTF_8);
			return X509Certificate.newCertificateFromPEM(cert);
		}

		LOGGER.debug("XFCC header does not contain a certificate. Certificate is set to null.");
		return null;
	}

	@Override
	public String getThumbprint() throws InvalidCertificateException {
		if (thumbprint == null) {
			try {
				this.thumbprint = X509Parser.getCertificateThumbprint(x509);
			} catch (NoSuchAlgorithmException | CertificateEncodingException e) {
				throw new InvalidCertificateException("Could not parse thumbprint", e);
			}
		}
		return this.thumbprint;
	}

	@Override
	public String getSubjectDN() {
		return x509.getSubjectX500Principal().getName(X500Principal.RFC1779).trim();
	}

	@Override
	public Map<String, String> getSubjectDNMap() {
		return Stream.of(getSubjectDN().split(",")).collect(Collectors.toMap(
				dn -> dn.split("=")[0].trim(),
				dn -> dn.split("=")[1],
				(dn1, dn2) -> dn1 + "," + dn2));
	}

	/**
	 * @return a base64 encoded DER certificate or certificate in PEM format
	 */
	public String getPEM() {
		return this.pem;
	}

}
