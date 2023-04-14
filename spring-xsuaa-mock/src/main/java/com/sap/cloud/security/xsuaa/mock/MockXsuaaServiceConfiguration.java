/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.mock;

import org.springframework.beans.factory.annotation.Value;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfigurationDefault;

public class MockXsuaaServiceConfiguration extends XsuaaServiceConfigurationDefault {

	@Value("${mockxsuaaserver.url:}")
	private String mockXsuaaServerUrl;

	@Override
	public String getUaaDomain() {
		if (!mockXsuaaServerUrl.isEmpty()) {
			return "localhost";
		}
		return super.getUaaDomain();
	}

	@Override
	public String getUaaUrl() {
		if (!mockXsuaaServerUrl.isEmpty()) {
			return mockXsuaaServerUrl;
		}
		return super.getUaaUrl();
	}

}