/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import javax.annotation.Nullable;

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
}
