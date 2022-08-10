/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
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

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_ZONE_UUID;
import static org.springframework.http.HttpMethod.GET;

public class SpringOAuth2TokenKeyService implements OAuth2TokenKeyService {

	private static final Logger LOGGER = LoggerFactory.getLogger(SpringOAuth2TokenKeyService.class);

	private final RestOperations restOperations;

	public SpringOAuth2TokenKeyService(@Nonnull RestOperations restOperations) {
		Assertions.assertNotNull(restOperations, "restOperations must not be null!");
		this.restOperations = restOperations;
	}

	@Override
	public String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String zoneId)
			throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		try {
			// create headers
			HttpHeaders headers = new HttpHeaders();
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
			headers.set(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());
			if (zoneId != null) {
				headers.set(X_ZONE_UUID, zoneId);
			}
			ResponseEntity<String> response = restOperations.exchange(
					tokenKeysEndpointUri, GET, new HttpEntity(headers), String.class);
			if (HttpStatus.OK.value() == response.getStatusCode().value()) {
				LOGGER.debug("Successfully retrieved token keys from {} for zone '{}'", tokenKeysEndpointUri, zoneId);
				return response.getBody();
			} else {
				throw OAuth2ServiceException.builder("Error retrieving token keys")
						.withUri(tokenKeysEndpointUri)
						.withHeaders(X_ZONE_UUID + "=" + zoneId)
						.withStatusCode(response.getStatusCodeValue())
						.withResponseBody(response.getBody())
						.build();
			}
		} catch (HttpStatusCodeException ex) {
			throw OAuth2ServiceException.builder("Error retrieving token keys")
					.withUri(tokenKeysEndpointUri)
					.withHeaders(X_ZONE_UUID + "=" + zoneId)
					.withStatusCode(ex.getStatusCode().value())
					.withResponseBody(ex.getResponseBodyAsString())
					.build();
		} catch (Exception e) {
			throw OAuth2ServiceException.builder("Unexpected error retrieving token keys: " + e.getMessage())
					.withUri(tokenKeysEndpointUri)
					.build();
		}
	}

}
