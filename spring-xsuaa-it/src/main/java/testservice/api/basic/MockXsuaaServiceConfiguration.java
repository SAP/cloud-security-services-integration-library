package testservice.api.basic;

import java.net.MalformedURLException;
import java.net.URL;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class MockXsuaaServiceConfiguration implements XsuaaServiceConfiguration {

	String url;
	private String appId;
	private String uaadomain;
	public MockXsuaaServiceConfiguration(String url, String appId) throws MalformedURLException {
		this.url = url;
		this.appId = appId;
		this.uaadomain = new URL(url).getHost();
	}

	@Override
	public String getClientId() {
		return "sb-"+appId;
	}

	@Override
	public String getClientSecret() {
		return "mysecret-basic";
	}

	@Override
	public String getUaaUrl() {
		return url;
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
		return uaadomain;
	}

}
