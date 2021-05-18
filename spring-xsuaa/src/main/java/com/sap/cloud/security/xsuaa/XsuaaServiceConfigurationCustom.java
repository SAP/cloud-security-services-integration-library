package com.sap.cloud.security.xsuaa;

import javax.annotation.Nullable;

public class XsuaaServiceConfigurationCustom implements XsuaaServiceConfiguration {

	private final XsuaaCredentials credentials;

	public XsuaaServiceConfigurationCustom(XsuaaCredentials credentials) {
		this.credentials = credentials;
	}

	@Override
	public String getClientId() {
		return credentials.getClientId();
	}

	@Override
	public String getClientSecret() {
		return credentials.getClientSecret();
	}

	@Override
	public String getUaaUrl() {
		return credentials.getUrl();
	}

	@Override
	public String getAppId() {
		return credentials.getXsAppName();
	}

	@Override
	public String getUaaDomain() {
		return credentials.getUaaDomain();
	}

	@Nullable
	@Override
	public String getVerificationKey() {
		return credentials.getVerificationKey();
	}

	@Nullable
	@Override
	public String getCertificates() {
		return credentials.getCertificate();
	}

	@Nullable
	@Override
	public String getPrivateKey() {
		return credentials.getPrivateKey();
	}

	@Nullable
	@Override
	public String getUaaCertUrl() {
		return credentials.getCertUrl();
	}

	@Override
	public String getCredentialType() {
		return credentials.getCredentialType();
	}
}
