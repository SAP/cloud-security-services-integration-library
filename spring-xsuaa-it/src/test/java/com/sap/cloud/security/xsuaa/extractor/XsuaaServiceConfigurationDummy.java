package com.sap.cloud.security.xsuaa.extractor;

import javax.annotation.Nullable;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class XsuaaServiceConfigurationDummy implements XsuaaServiceConfiguration {

	String clientId;
	String clientSecret;
	String uaaUrl;
	String uaaDomain;
	String appId;

	@Override
	public String getClientId() {
		return clientId;
	}

	@Override
	public String getClientSecret() {
		return clientSecret;
	}

	@Override
	public String getUaaUrl() {
		return uaaUrl;
	}

	@Override
	public String getAppId() {
		return appId;
	}

	@Override
	public String getUaaDomain() {
		return uaaDomain;
	}

	@Nullable @Override public String getCertificates() {
		return null;
	}

	@Nullable @Override public String getPrivateKey() {
		return null;
	}

}
