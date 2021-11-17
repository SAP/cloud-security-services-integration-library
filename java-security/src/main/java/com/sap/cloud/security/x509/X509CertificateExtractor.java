package com.sap.cloud.security.x509;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static com.sap.cloud.security.x509.X509Constants.FWD_CLIENT_CERT_HEADER;

/**
 * X509 certificate extractor.
 */
public class X509CertificateExtractor {

	private static final Logger LOGGER = LoggerFactory.getLogger(X509CertificateExtractor.class);

	private X509CertificateExtractor() {
		//use factory method instead
	}

	public static X509CertificateExtractor getInstance() {
		return new X509CertificateExtractor();
	}

	/**
	 * Extracts the forwarded client certificate from 'x-forwarded-client-cert' header.
	 *
	 * @param request the HttpServletRequest
	 * @return the client certificate object
	 */
	@Nullable
	public X509Certificate getClientCertificate(HttpServletRequest request) {
		String clientCert = request.getHeader(FWD_CLIENT_CERT_HEADER);
		LOGGER.debug("{} = {}", FWD_CLIENT_CERT_HEADER, clientCert);
		if (clientCert != null && !clientCert.isEmpty()){
			try {
				return X509Parser.parseCertificate(clientCert);
			} catch (CertificateException e) {
				LOGGER.debug("Could not parse the certificate", e);
			}
		}
		return null;
	}

}
