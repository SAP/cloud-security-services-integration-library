package com.sap.cloud.security.token.x509;

import javax.servlet.http.HttpServletRequest;

/**
 * Interface for accessing X509 certificates.
 */
public interface X509CertSelector {

	String getCertificate(HttpServletRequest request);
}
