/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import javax.annotation.Nonnull;
import java.net.URI;

import static com.sap.cloud.security.xsuaa.http.HttpHeaders.X_ZONE_UUID;
import static org.springframework.http.HttpMethod.GET;

public class SpringOAuth2TokenKeyService implements OAuth2TokenKeyService {
	private final RestOperations restOperations;

	public SpringOAuth2TokenKeyService(@Nonnull RestOperations restOperations) {
		Assertions.assertNotNull(restOperations, "restOperations must not be null!");
		this.restOperations = restOperations;
	}

	@Override
	public String retrieveTokenKeys(URI tokenKeysEndpointUri, String zoneId) throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		try {
			MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
			headers.add(X_ZONE_UUID, zoneId);
			ResponseEntity<String> response = restOperations.exchange(
					tokenKeysEndpointUri, GET, new HttpEntity<>(headers), String.class);
			if (HttpStatus.OK.value() == response.getStatusCode().value()) {
				return response.getBody();
			} else {
				throw OAuth2ServiceException.builder("Error retrieving token keys")
						.withUri(tokenKeysEndpointUri)
						.withHeaders(X_ZONE_UUID + "=" + zoneId)
						.withStatusCode(response.getStatusCodeValue())
						.withResponseBody(response.getBody())
						.build();
			}
		} catch (HttpClientErrorException ex) {
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
