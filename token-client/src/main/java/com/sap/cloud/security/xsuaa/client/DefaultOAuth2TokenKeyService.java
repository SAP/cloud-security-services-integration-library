/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_ZONE_UUID;

public class DefaultOAuth2TokenKeyService implements OAuth2TokenKeyService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DefaultOAuth2TokenKeyService.class);

	private final CloseableHttpClient httpClient;

	public DefaultOAuth2TokenKeyService() {
		httpClient = HttpClientFactory.create(null);
	}

	public DefaultOAuth2TokenKeyService(@Nonnull CloseableHttpClient httpClient) {
		Assertions.assertNotNull(httpClient, "httpClient is required");
		this.httpClient = httpClient;
	}

	@Override
	public String retrieveTokenKeys(URI tokenKeysEndpointUri, @Nullable String zoneId) throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		HttpUriRequest request = new HttpGet(tokenKeysEndpointUri); // lgtm[java/ssrf] tokenKeysEndpointUri is validated
																	// as part of XsuaaJkuValidator in java-security
		if (zoneId != null) {
			request.addHeader(X_ZONE_UUID, zoneId);
		}
		request.addHeader(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());

		LOGGER.debug("Executing token key retrieval GET request to {} with headers: {} ", tokenKeysEndpointUri,
				request.getHeaders());
		try {
			String jwksJson = httpClient.execute(request, response -> {
				int statusCode = response.getCode();
				LOGGER.debug("Received statusCode {}", statusCode);
				String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
				if (statusCode != HttpStatus.SC_OK) {
					throw OAuth2ServiceException.builder("Error retrieving token keys for x-zone_uuid " + zoneId)
							.withUri(tokenKeysEndpointUri)
							.withHeaders(X_ZONE_UUID + "=" + zoneId)
							.withStatusCode(statusCode)
							.withResponseBody(body)
							.build();
				}

				LOGGER.debug("Successfully retrieved token keys from {} for zone '{}'", tokenKeysEndpointUri, zoneId);
				return body;
			});

			return jwksJson;
		} catch (IOException e) {
			throw new OAuth2ServiceException("Error retrieving token keys: " + e.getMessage());
		}
	}

}
