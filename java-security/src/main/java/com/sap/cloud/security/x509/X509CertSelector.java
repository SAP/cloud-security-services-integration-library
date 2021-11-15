package com.sap.cloud.security.x509;

import com.sap.cloud.security.config.Environment;
import com.sap.cloud.security.config.Environments;

import javax.servlet.http.HttpServletRequest;

/**
 * Interface for accessing X509 certificates.
 */
public interface X509CertSelector {

	String getClientCertificate(HttpServletRequest request);

	static X509CertSelector create() {
		if (Environments.getCurrent().getType() == Environment.Type.CF) {
			return new CFx509CertSelector();
		} else
			return new K8sX509CertSelector();
	}
}
