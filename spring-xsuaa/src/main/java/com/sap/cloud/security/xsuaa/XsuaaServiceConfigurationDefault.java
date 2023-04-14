/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.net.URI;
import java.util.Objects;

@Configuration
public class XsuaaServiceConfigurationDefault implements XsuaaServiceConfiguration {

	static final String VCAP_SERVICES_CREDENTIALS = "xsuaa credentials from VCAP_SERVICES/secret must not be null";

	@Value("${xsuaa.clientid:}")
	private String clientId;

	@Value("${xsuaa.clientsecret:}")
	private String clientSecret;

	@Value("${xsuaa.url:}")
	private String uaaUrl;

	@Value("${xsuaa.uaadomain:#{null}}")
	private String uaadomain;

	@Value("${xsuaa.xsappname:}")
	private String appid;

	@Value("${xsuaa.key:}")
	private String privateKey;

	@Value("${xsuaa.certificate:}")
	private String certificate;

	@Value("${xsuaa.verificationkey:}")
	private String verificationKey;

	@Value("${xsuaa.credential-type:#{null}}")
	private String credentialType;

	@Value("${xsuaa.certurl:#{null}}")
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

	@Override
	public ClientIdentity getClientIdentity() {
		ClientIdentity identity = new ClientCertificate(certificate, privateKey, getClientId());
		if (!identity.isValid()) {
			identity = new ClientCredentials(getClientId(), getClientSecret());
		}
		return identity;
	}

	/**
	 * This only supports read from VCAP_SERVICES in cf environment or read from
	 * secrets in kubernetes environment.
	 * 
	 * @param name
	 *            of the credential property
	 * @return the property value or null if not found
	 */
	@Override
	public String getProperty(String name) {
		return Objects.requireNonNull(Environments.getCurrent().getXsuaaConfiguration(), VCAP_SERVICES_CREDENTIALS)
				.getProperty(name);
	}

	/**
	 * This only supports VCAP_SERVICES in cf environment or read from secrets in
	 * kubernetes environment.
	 * 
	 * @param name
	 *            of the credential property
	 * @return false if property doesn't exist
	 */
	@Override
	public boolean hasProperty(String name) {
		return Objects.requireNonNull(Environments.getCurrent().getXsuaaConfiguration(), VCAP_SERVICES_CREDENTIALS)
				.hasProperty(name);
	}
}
