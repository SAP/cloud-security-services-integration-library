/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.ClientCertificate;
import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.CredentialType;

import javax.annotation.Nullable;
import java.net.URI;

public class XsuaaServiceConfigurationCustom implements XsuaaServiceConfiguration {

	private final XsuaaCredentials credentials;

	public XsuaaServiceConfigurationCustom(XsuaaCredentials credentials) {
		this.credentials = credentials;
	}

	@Override
	public String getClientId() {
		return credentials.getClientId();
	}

	@Override
	public String getClientSecret() {
		return credentials.getClientSecret();
	}

	@Override
	public String getUaaUrl() {
		return credentials.getUrl();
	}

	@Nullable
	@Override
	public URI getCertUrl() {
		String certUrl = credentials.getCertUrl();
		return certUrl == null ? null : URI.create(certUrl);
	}

	@Override
	public String getAppId() {
		return credentials.getXsAppName();
	}

	@Override
	public String getUaaDomain() {
		return credentials.getUaaDomain();
	}

	@Nullable
	@Override
	public String getVerificationKey() {
		return credentials.getVerificationKey();
	}

	@Override
	public CredentialType getCredentialType() {
		return credentials.getCredentialType();
	}

	@Override
	public String getProperty(String name) {
		return null;
	}

	@Override
	public ClientIdentity getClientIdentity() {
		ClientIdentity identity = new ClientCertificate(credentials.getCertificate(), credentials.getKey(),
				getClientId());
		if (!identity.isValid()) {
			identity = new ClientCredentials(getClientId(), getClientSecret());
		}
		return identity;
	}
}
