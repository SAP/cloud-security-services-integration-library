package com.sap.cloud.security.xsuaa;
/**
 * 
 */

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class XsuaaServiceConfigurationDefault implements XsuaaServiceConfiguration {

	@Value("${xsuaa.clientid:}")
	private String clientId;

	@Value("${xsuaa.clientsecret:}")
	private String clientSecret;

	@Value("${xsuaa.url:}")
	private String uaaUrl;

	@Value("${xsuaa.uaadomain:#{null}}")
	private String uaadomain;

	@Value("${xsuaa.identityzoneid:}")
	private String identityZoneId;

	@Value("${xsuaa.xsappname:}")
	private String appid;

	@Value("${xsuaa.key:}")
	private String privateKey;

	@Value("${xsuaa.certificate:}")
	private String certificates;

	@Value("${xsuaa.verificationkey:}")
	private String verificationKey;

	/*
	 * (non-Javadoc)
	 *
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getClientId()
	 */
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
		return this.appid;
	}

	@Override
	public String getUaaDomain() {
		return uaadomain;
	}

	@Override
	public String getVerificationKey() {
		return verificationKey;
	}

	/*
	 * @Override public String getCertificates() { return certificates; }
	 * 
	 * @Override public String getPrivateKey() { return privateKey; }
	 */
}
