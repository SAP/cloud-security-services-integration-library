/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.CredentialType;

public class DummyXsuaaServiceConfiguration implements XsuaaServiceConfiguration {

	private String clientId;
	private String uaaDomain;
	private String appId;

	public DummyXsuaaServiceConfiguration() {
	}

	public DummyXsuaaServiceConfiguration(String clientId, String appId) {
		this.clientId = clientId;
		this.appId = appId;
	}

	@Override
	public String getClientId() {
		return clientId != null ? clientId : "clientId";
	}

	@Override
	public String getClientSecret() {
		return "secret";
	}

	@Override
	public String getUaaUrl() {
		return "https://subdomain.authentication.eu10.hana.ondemand.com";
	}

	@Override
	public String getAppId() {
		return appId;
	}

	@Override
	public String getUaaDomain() {
		return uaaDomain;
	}

	@Override
	public String getVerificationKey() {
		return null;
	}

	@Override
	public CredentialType getCredentialType() {
		return null;
	}

	@Override
	public ClientIdentity getClientIdentity() {
		return new ClientCredentials(getClientId(), getClientSecret());
	}

}
