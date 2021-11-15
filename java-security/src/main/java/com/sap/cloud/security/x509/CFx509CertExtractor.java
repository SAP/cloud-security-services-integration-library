package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;

/**
 * X509 certificate accessor implementation for Cloud Foundry environment.
 */
public class CFx509CertExtractor implements X509CertExtractor {

	private static final Logger LOGGER = LoggerFactory.getLogger(CFx509CertExtractor.class);

	@Override
	@Nullable
	public String getClientCertificate(HttpServletRequest request) {
		String clientCert = request.getHeader(FWD_CLIENT_CERT_HEADER);
		LOGGER.debug("{} = {}", FWD_CLIENT_CERT_HEADER, clientCert);
		return clientCert;
	}

}
