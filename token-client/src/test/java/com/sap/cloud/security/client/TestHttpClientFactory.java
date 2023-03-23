/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.mockito.Mockito;

public class TestHttpClientFactory implements HttpClientFactory {

	@Override
	public CloseableHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		return Mockito.mock(CloseableHttpClient.class);
	}
}
