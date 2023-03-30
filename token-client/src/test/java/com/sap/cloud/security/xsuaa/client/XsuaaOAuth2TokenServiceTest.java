/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.tokenflows.TokenCacheConfiguration;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.web.client.RestOperations;

public class XsuaaOAuth2TokenServiceTest {

	@Test(expected = IllegalArgumentException.class)
	public void initialize_throwsIfRestOperationsIsNull() {
		new XsuaaOAuth2TokenService(null, TokenCacheConfiguration.cacheDisabled());
	}

	@Test(expected = IllegalArgumentException.class)
	public void initialize_throwsIfCacheConfigurationIsNull() {
		new XsuaaOAuth2TokenService(Mockito.mock(RestOperations.class), null);
	}

}