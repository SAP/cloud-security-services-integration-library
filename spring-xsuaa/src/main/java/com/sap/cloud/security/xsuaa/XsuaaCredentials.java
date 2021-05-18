package com.sap.cloud.security.xsuaa;

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
	private String credentialType;

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

	public String getCertUrl() { return certUrl; }

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

	public String getCredentialType() {
		return credentialType;
	}

	public void setCredentialType(String credentialType) {
		this.credentialType = credentialType;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}
}
