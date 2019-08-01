package com.sap.cloud.security.xsuaa;

public class DummyXsuaaServiceConfiguration implements XsuaaServiceConfiguration {

	private String clientId;
	private String uaaDomain;
	private String appId;

	public DummyXsuaaServiceConfiguration() {
	}

	public DummyXsuaaServiceConfiguration(String clientId, String appId) {
		this.clientId = clientId;
		this.appId = appId;
	}

	@Override
	public String getClientId() {
		return clientId;
	}

	@Override
	public String getClientSecret() {
		return null;
	}

	@Override
	public String getUaaUrl() {
		return null;
	}

	@Override
	public String getTokenKeyUrl(String zid, String subdomain) {
		return null;
	}

	@Override
	public String getAppId() {
		return appId;
	}

	@Override
	public String getUaaDomain() {
		return uaaDomain;
	}
}
