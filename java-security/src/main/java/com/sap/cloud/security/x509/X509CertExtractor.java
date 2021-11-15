package com.sap.cloud.security.x509;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;

import javax.servlet.http.HttpServletRequest;

/**
 * Interface for accessing X509 certificates.
 */
public interface X509CertExtractor {

	String getClientCertificate(HttpServletRequest request);

	static X509CertExtractor create() {
		if (Environments.getCurrent().getType() == Environment.Type.CF) {
			return new CFx509CertExtractor();
		} else
			return new K8sX509CertExtractor();
	}
}
