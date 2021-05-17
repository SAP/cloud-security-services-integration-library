/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class XsuaaServiceConfigurationCustomTest {
	XsuaaCredentials credentials = new XsuaaCredentials();
	XsuaaServiceConfigurationCustom cut;

	@BeforeEach
	public void setup() {
		credentials.setClientId("cid");
		credentials.setClientSecret("secret");
		credentials.setUaaDomain("uaaDomain");
		credentials.setUrl("url");
		credentials.setXsAppName("xsappname");

		cut = new XsuaaServiceConfigurationCustom(credentials);
	}

	@Test
	public void getterShouldReturnValuesFromCredentials() {
		assertEquals(credentials.getClientId(), cut.getClientId());
		assertEquals(credentials.getClientSecret(), cut.getClientSecret());
		assertEquals(credentials.getUaaDomain(), cut.getUaaDomain());
		assertEquals(credentials.getUrl(), cut.getUaaUrl());
		assertEquals(credentials.getXsAppName(), cut.getAppId());
	}

	@Test
	public void getVerificationKeyIsNull() {
		assertNull(cut.getVerificationKey());
	}
}
