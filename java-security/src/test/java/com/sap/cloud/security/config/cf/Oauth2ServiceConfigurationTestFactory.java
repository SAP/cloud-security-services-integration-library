package com.sap.cloud.security.config.cf;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;

import java.util.HashMap;
import java.util.Map;

public class Oauth2ServiceConfigurationTestFactory {

	public static final String APP_ID = "appId";
	public static final String CLIENT_ID = "clientId";
	public static final String UAA_DOMAIN = "auth.com";

	public OAuth2ServiceConfiguration createXsuaaConfiguration() {
		Map<String, String> credentials = new HashMap<>();
		credentials.put(CFConstants.XSUAA.APP_ID, APP_ID);
		credentials.put(CFConstants.CLIENT_ID, CLIENT_ID);
		credentials.put(CFConstants.XSUAA.UAA_DOMAIN, UAA_DOMAIN);
		return new CFOAuth2ServiceConfiguration(Service.XSUAA, new HashMap<>(), credentials);
	}
}