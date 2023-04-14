/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class XsuaaServiceConfigurationDummy implements XsuaaServiceConfiguration {

	String clientId;
	String clientSecret;
	String uaaUrl;
	String uaaDomain;
	String appId;
	String verificationKey;

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
		return appId;
	}

	@Override
	public String getUaaDomain() {
		return uaaDomain;
	}

	@Override
	public String getVerificationKey() {
		return verificationKey;
	}

	// TODO remove once credential-type is available in IAS configuration
	@Override
	public String getProperty(String name) {
		return null;
	}

	@Override
	public ClientIdentity getClientIdentity() {
		return new ClientCredentials(getClientId(), getClientSecret());
	}

}
