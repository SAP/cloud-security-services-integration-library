/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import javax.annotation.Nullable;

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

	@Nullable
	@Override
	public String getUaaCertUrl() {
		return null;
	}

	@Override
	public String getCredentialType() {
		return null;
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

	@Nullable
	@Override
	public String getCertificates() {
		return null;
	}

	@Nullable
	@Override
	public String getPrivateKey() {
		return null;
	}

}
