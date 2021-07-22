/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.CredentialType;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;


@ConfigurationProperties("xsuaa")
public class XsuaaServiceConfigurationDefault implements XsuaaServiceConfiguration {

	private String clientId = "";

	private String clientSecret = "";

	private String uaaUrl = "";

	private String uaadomain = "";

	private String identityZoneId;

	private String appid = "";

	private String privateKey;

	private String certificate;

	private String verificationKey;

	private String credentialType;

	private String certUrl;

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
	public ClientIdentity getClientIdentity() {
		if (getCredentialType() == CredentialType.X509) {
			return new ClientCertificate(certificate, privateKey, getClientId());
		}
		return new ClientCredentials(getClientId(), getClientSecret());
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

	@Override
	public CredentialType getCredentialType() {
		return CredentialType.from(credentialType);
	}

	@Override
	public URI getCertUrl() {
		return URI.create(certUrl);
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public void setUrl(String url) {
		this.uaaUrl = url;
	}

	public void setUaaDomain(String uaadomain) {
		this.uaadomain = uaadomain;
	}

	public void setIdentityZoneId(String identityZoneId) {
		this.identityZoneId = identityZoneId;
	}

	public void setXsappname(String xsappname) {
		this.appid = xsappname;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	public void setVerificationKey(String verificationKey) {
		this.verificationKey = verificationKey;
	}

	public void setCredentialType(String credentialType) {
		this.credentialType = credentialType;
	}

	public void setCertUrl(String certUrl) {
		this.certUrl = certUrl;
	}
}
