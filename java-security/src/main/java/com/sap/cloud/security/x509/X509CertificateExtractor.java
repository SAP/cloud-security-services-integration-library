/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;

/**
 * X509 certificate extractor.
 */
public class X509CertificateExtractor {

	private static final Logger LOGGER = LoggerFactory.getLogger(X509CertificateExtractor.class);

	private X509CertificateExtractor() {
		// use factory method instead
	}

	public static X509CertificateExtractor getInstance() {
		return new X509CertificateExtractor();
	}

	/**
	 * Extracts the forwarded client certificate from 'x-forwarded-client-cert'
	 * header.
	 *
	 * @param request
	 *            the HttpServletRequest
	 * @return the client certificate object
	 */
	@Nullable
	public String getClientCertificate(HttpServletRequest request) {
		String clientCert = request.getHeader(FWD_CLIENT_CERT_HEADER);
		LOGGER.debug("{} = {}", FWD_CLIENT_CERT_HEADER, clientCert);
		return clientCert;
	}

}
