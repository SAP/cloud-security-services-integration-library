/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.client.HttpClientFactory;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_OSB_PLAN;

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
	public String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, Map<String, String> params)
			throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		HttpUriRequest request = new HttpGet(tokenKeysEndpointUri);

		for (Map.Entry<String, String> p : params.entrySet()) {
			request.addHeader(p.getKey(), p.getValue());
		}
		request.addHeader(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());

		LOGGER.debug("Executing token key retrieval GET request to {} with headers: {} ", tokenKeysEndpointUri,
				request.getAllHeaders());
		try {
			return httpClient.execute(request, response -> {
				int statusCode = response.getStatusLine().getStatusCode();
				LOGGER.debug("Received statusCode {}", statusCode);
				String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
				if (statusCode != HttpStatus.SC_OK) {
					throw OAuth2ServiceException
							.builder("Error retrieving token keys. Request headers "
									+ Arrays.stream(request.getAllHeaders()).toList())
							.withUri(tokenKeysEndpointUri)
							.withHeaders(response.getAllHeaders() != null ? Arrays.stream(response.getAllHeaders())
									.map(Header::toString).toArray(String[]::new) : null)
							.withStatusCode(statusCode)
							.withResponseBody(body)
							.build();
				}

				LOGGER.debug("Successfully retrieved token keys from {} with params {}.", tokenKeysEndpointUri, params);

				/* This is required for Identity Service App2Service communication. When proof token validation is enabled,
				 the response can contain an Identity Service broker plan header whose content needs to be accessible
				 on the SecurityContext. */
				if (response.containsHeader(X_OSB_PLAN)) {
					String xOsbPlan = response.getFirstHeader(X_OSB_PLAN).getValue();
					if (xOsbPlan != null) {
						SecurityContext.setServicePlans(xOsbPlan);
					}
				}

				return body;
			});
		} catch (IOException e) {
			if (e instanceof OAuth2ServiceException oAuth2Exception) {
				throw oAuth2Exception;
			} else {
				throw new OAuth2ServiceException("Error retrieving token keys: " + e.getMessage());
			}
		}
	}

}
