/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import org.mockito.Mockito;

/**
 * Test implementation of SecurityHttpClientFactory with high priority
 * to verify ServiceLoader priority mechanism.
 */
public class TestSecurityHttpClientFactory implements SecurityHttpClientFactory {

	@Override
	public SecurityHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		SecurityHttpClient mock = Mockito.mock(SecurityHttpClient.class, "MockSecurityHttpClient");
		return mock;
	}

	@Override
	public int getPriority() {
		return 100; // Higher than default (0)
	}
}
