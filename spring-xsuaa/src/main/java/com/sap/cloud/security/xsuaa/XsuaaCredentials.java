package com.sap.cloud.security.xsuaa;

/**
 * Represents the XSUAA credentials of VCAP_SERVICES.
 */
public class XsuaaCredentials {
	private String clientId;
	private String clientSecret;
	private String url;
	private String uaaDomain;
	private String xsAppName;

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
}
