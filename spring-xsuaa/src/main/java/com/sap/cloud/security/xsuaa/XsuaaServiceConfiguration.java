package com.sap.cloud.security.xsuaa;


public interface XsuaaServiceConfiguration {

	String getClientId();

	String getClientSecret();

	String getUaaUrl();
	
	String getTokenKeyUrl(String zid, String subdomain);

	String getAppId();
}