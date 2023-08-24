/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestOperations;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Collections;
import java.util.stream.Collectors;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_APP_TID;
import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_CLIENT_ID;
import static org.springframework.http.HttpMethod.GET;

public class SpringOAuth2TokenKeyService implements OAuth2TokenKeyService {

	private static final Logger LOGGER = LoggerFactory.getLogger(SpringOAuth2TokenKeyService.class);

	private final RestOperations restOperations;

	public SpringOAuth2TokenKeyService(@Nonnull RestOperations restOperations) {
		Assertions.assertNotNull(restOperations, "restOperations must not be null!");
		this.restOperations = restOperations;
	}

	@Override
	public String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String tenantId)
			throws OAuth2ServiceException {
		return retrieveTokenKeys(tokenKeysEndpointUri, tenantId, null);
	}

	@Override
	public String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String tenantId, @Nullable String clientId)
			throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		headers.set(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
		if (tenantId != null && clientId != null) {
			headers.set(X_APP_TID, tenantId);
			headers.set(X_CLIENT_ID, clientId);
		}
		try {
			ResponseEntity<String> response = restOperations.exchange(
					tokenKeysEndpointUri, GET, new HttpEntity<>(headers), String.class);
			if (HttpStatus.OK.value() == response.getStatusCode().value()) {
				LOGGER.debug("Successfully retrieved token keys from {} for tenant '{}'", tokenKeysEndpointUri, tenantId);
				return response.getBody();
			} else {
				throw OAuth2ServiceException.builder(
								"Error retrieving token keys. Request headers [" + headers.entrySet().stream()
										.map(h -> h.getKey() + ": " + String.join(",", h.getValue()))
										.collect(Collectors.joining(", ")) + "]")
						.withUri(tokenKeysEndpointUri)
						.withHeaders(response.getHeaders().size() != 0 ? response.getHeaders().entrySet().stream().map(
										h -> h.getKey() + ": " + String.join(",", h.getValue()))
								.toArray(String[]::new) : null)
						.withStatusCode(response.getStatusCodeValue())
						.withResponseBody(response.getBody())
						.build();
			}
		} catch (HttpStatusCodeException ex) {
			throw OAuth2ServiceException.builder(
							"Error retrieving token keys. Request headers [" + headers.entrySet().stream()
							.map(h -> h.getKey() + ": " + String.join(",", h.getValue())))
					.withUri(tokenKeysEndpointUri)
					.withHeaders(ex.getResponseHeaders() != null ? ex.getResponseHeaders().entrySet().stream().map(
									h -> h.getKey() + ": " + String.join(",", h.getValue()))
							.toArray(String[]::new) : null)
					.withStatusCode(ex.getStatusCode().value())
					.withResponseBody(ex.getResponseBodyAsString())
					.build();
		} catch (Exception e) {
			if (e instanceof OAuth2ServiceException ) {
				throw (OAuth2ServiceException) e;
			} else {
				throw OAuth2ServiceException.builder("Unexpected error retrieving token keys: " + e.getMessage())
						.withUri(tokenKeysEndpointUri)
						.build();
			}
		}
	}

}
