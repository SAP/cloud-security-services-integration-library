/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.client;

import com.sap.cloud.security.config.ClientIdentity;

/**
 * @deprecated Use {@link SecurityHttpClientProvider} with {@link JavaHttpClientFactory}
 * or {@link com.sap.cloud.security.client.apache.ApacheHttpClientFactory} instead.
 * This class is kept for backward compatibility in the legacy module.
 */
@Deprecated(since = "4.0.0", forRemoval = true)
public class DefaultHttpClientFactory implements HttpClientFactory {

	@Override
	public SecurityHttpClient createClient(ClientIdentity clientIdentity) throws HttpClientException {
		return SecurityHttpClientProvider.createClient(clientIdentity);
	}
}
