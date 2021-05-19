/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;

public class DefaultOAuth2TokenKeyService implements OAuth2TokenKeyService {

	private final CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyService() {
		httpClient = HttpClients.createDefault();
	}

	public DefaultOAuth2TokenKeyService(@Nonnull CloseableHttpClient httpClient) {
		Assertions.assertNotNull(httpClient, "httpClient is required");
		this.httpClient = httpClient;
	}

	@Override
	public String retrieveTokenKeys(URI tokenKeysEndpointUri) throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		HttpUriRequest request = new HttpGet(tokenKeysEndpointUri);
		try (CloseableHttpResponse response = httpClient.execute(request)) {
			String bodyAsString = HttpClientUtil.extractResponseBodyAsString(response);
			int statusCode = response.getStatusLine().getStatusCode();
			if (statusCode == HttpStatus.SC_OK) {
				return bodyAsString;
			} else {
				throw OAuth2ServiceException.builder("Error retrieving token keys")
						.withUri(tokenKeysEndpointUri)
						.withStatusCode(statusCode)
						.withResponseBody(bodyAsString)
						.build();
			}
		} catch (IOException e) {
			throw new OAuth2ServiceException("Error retrieving token keys: " + e.getMessage());
		}
	}

}
