/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.CredentialType;

/**
 * Represents the XSUAA credentials of VCAP_SERVICES.
 */
public class XsuaaCredentials {
	private String clientId;
	private String clientSecret;
	private String url;
	private String certUrl;
	private String uaaDomain;
	private String xsAppName;
	private String verificationKey;
	private String certificate;
	private String privateKey;
	private CredentialType credentialType;

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getCertUrl() {
		return certUrl;
	}

	public void setCertUrl(String certUrl) {
		this.certUrl = certUrl;
	}

	public String getUaaDomain() {
		return uaaDomain;
	}

	public void setUaaDomain(String uaaDomain) {
		this.uaaDomain = uaaDomain;
	}

	public String getXsAppName() {
		return xsAppName;
	}

	public void setXsAppName(String xsAppName) {
		this.xsAppName = xsAppName;
	}

	public String getVerificationKey() {
		return verificationKey;
	}

	public void setVerificationKey(String verificationKey) {
		this.verificationKey = verificationKey;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	public CredentialType getCredentialType() {
		return credentialType;
	}

	public void setCredentialType(CredentialType credentialType) {
		this.credentialType = credentialType;
	}

	public String getKey() {
		return privateKey;
	}

	public void setKey(String privateKey) {
		this.privateKey = privateKey;
	}
}
