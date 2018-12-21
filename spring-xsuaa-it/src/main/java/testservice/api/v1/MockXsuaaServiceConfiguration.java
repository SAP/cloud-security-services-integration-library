package testservice.api.v1;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class MockXsuaaServiceConfiguration implements XsuaaServiceConfiguration {

	String url;
	private String appId;

	public MockXsuaaServiceConfiguration(String url, String appId) {
		this.url = url;
		this.appId = appId;
	}

	@Override
	public String getClientId() {
		return "sb-"+appId;
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
		return url + "/" + subdomain + "/token_keys";
	}

	@Override
	public String getAppId() {
		return appId;
	}

	@Override
	public String getUaaDomain() {
		return null;
	}

}
