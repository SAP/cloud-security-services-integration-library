package com.sap.cloud.security.xsuaa;

public interface ServiceConfiguration {

	String getClientId();

	void setClientId(String clientId);

	String getClientSecret();

	void setClientSecret(String clientSecret);

	String getUaaUrl();

	void setUaaUrl(String uaaUrl);

	String getUaadomain();

	void setUaadomain(String uaadomain);

	String getIdentityZoneId();

	void setIdentityZoneId(String identityZoneId);

	String getVerificationKey();

	void setVerificationKey(String verificationKey);

	String getTrustedClientIdSuffix();

	void setTrustedClientIdSuffix(String trustedClientIdSuffix);

	String getXsappname();

	void setXsappname(String xsappname);

	String getPlatformClientId();

	void setPlatformClientId(String clientId);

	String getPlatformClientSecret();

	void setPlatformClientSecret(String clientSecret);

	String getPlatformUrl();

	void setPlatformUrl(String uaaUrl);

}