/**
 * 
 */
package com.sap.cloud.security.xsuaa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(factory = PlatformPropertySourceFactory.class, value = { "" })
public class PlatformConfiguration implements ServiceConfiguration {

	@Value("${vcap.services.user-provided.credentials.xsuaa.validation.clientid:}")
	private String clientId;

	@Value("${vcap.services.user-provided.credentials.xsuaa.validation.clientsecret:}")
	private String clientSecret;

	@Value("${vcap.services.user-provided.credentials.xsuaa.validation.uaaurl:}")
	private String uaaUrl;

	@Value("${vcap.services.user-provided.credentials.uaadomain:}")
	private String uaadomain;

	@Value("${vcap.services.user-provided.credentials.identityzoneid:}")
	private String identityZoneId;

	@Value("${vcap.services.user-provided.credentials.verificationkey:}")
	private String verificationKey;

	@Value("${xsuaa.trustedclientidsuffix:}")
	private String trustedClientIdSuffix;

	@Value("${vcap.services.user-provided.name:}")
	private String xsappname;

	@Value("${vcap.services.user-provided.credentials.authentication.clientid:}")
	private String platformClientId;

	@Value("${vcap.services.user-provided.credentials.authentication.clientsecret:}")
	private String platformClientSecret;

	@Value("${vcap.services.user-provided.credentials.authentication.uaaurl:}")
	private String platformUrl;

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getClientId()
	 */
	@Override
	public String getClientId() {
		return clientId;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setClientId(java.lang.String)
	 */
	@Override
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getClientSecret()
	 */
	@Override
	public String getClientSecret() {
		return clientSecret;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setClientSecret(java.lang.String)
	 */
	@Override
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getUaaUrl()
	 */
	@Override
	public String getUaaUrl() {
		return uaaUrl;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setUaaUrl(java.lang.String)
	 */
	@Override
	public void setUaaUrl(String uaaUrl) {
		this.uaaUrl = uaaUrl;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getUaadomain()
	 */
	@Override
	public String getUaadomain() {
		return uaadomain;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setUaadomain(java.lang.String)
	 */
	@Override
	public void setUaadomain(String uaadomain) {
		this.uaadomain = uaadomain;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getIdentityZoneId()
	 */
	@Override
	public String getIdentityZoneId() {
		return identityZoneId;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setIdentityZoneId(java.lang.String)
	 */
	@Override
	public void setIdentityZoneId(String identityZoneId) {
		this.identityZoneId = identityZoneId;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getVerificationKey()
	 */
	@Override
	public String getVerificationKey() {
		return verificationKey;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setVerificationKey(java.lang.String)
	 */
	@Override
	public void setVerificationKey(String verificationKey) {
		this.verificationKey = verificationKey;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getTrustedClientIdSuffix()
	 */
	@Override
	public String getTrustedClientIdSuffix() {
		return trustedClientIdSuffix;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setTrustedClientIdSuffix(java.lang.String)
	 */
	@Override
	public void setTrustedClientIdSuffix(String trustedClientIdSuffix) {
		this.trustedClientIdSuffix = trustedClientIdSuffix;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#getXsappname()
	 */
	@Override
	public String getXsappname() {
		return xsappname;
	}

	/* (non-Javadoc)
	 * @see com.sap.cloud.security.xsuaa.ServiceConfiguration#setXsappname(java.lang.String)
	 */
	@Override
	public void setXsappname(String xsappname) {
		this.xsappname = xsappname;
	}

	public String getPlatformClientId() {
		return platformClientId;
	}

	public void setPlatformClientId(String platformClientId) {
		this.platformClientId = platformClientId;
	}

	public String getPlatformClientSecret() {
		return platformClientSecret;
	}

	public void setPlatformClientSecret(String platformClientSecret) {
		this.platformClientSecret = platformClientSecret;
	}

	public String getPlatformUrl() {
		return platformUrl;
	}

	public void setPlatformUrl(String platformUrl) {
		this.platformUrl = platformUrl;
	}

}
