/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;

import java.net.URI;

import com.sap.cloud.security.xsuaa.util.HttpClientUtil;
import org.springframework.http.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import com.sap.cloud.security.xsuaa.Assertions;

public class SpringOidcConfigurationService implements OidcConfigurationService {
	private final RestOperations restOperations;

	public SpringOidcConfigurationService(@Nonnull RestOperations restOperations) {
		Assertions.assertNotNull(restOperations, "restOperations must not be null!");
		this.restOperations = restOperations;
	}

	@Override
	public OAuth2ServiceEndpointsProvider retrieveEndpoints(@Nonnull URI discoveryEndpointUri)
			throws OAuth2ServiceException {
		Assertions.assertNotNull(discoveryEndpointUri, "discoveryEndpointUri must not be null!");
		try {
			HttpHeaders headers = new HttpHeaders();
			headers.set(HttpHeaders.USER_AGENT, HttpClientUtil.getUserAgent());

			ResponseEntity<String> response = restOperations.exchange(discoveryEndpointUri, HttpMethod.GET,
					new HttpEntity(headers), String.class);
			if (HttpStatus.OK.value() == response.getStatusCode().value()) {
				return new DefaultOidcConfigurationService.OidcEndpointsProvider(response.getBody());
			} else {
				throw OAuth2ServiceException.builder("Error retrieving configured oidc endpoints")
						.withUri(discoveryEndpointUri)
						.withStatusCode(response.getStatusCodeValue())
						.withResponseBody(response.getBody())
						.build();
			}
		} catch (HttpClientErrorException ex) {
			throw OAuth2ServiceException.builder("Error retrieving configured oidc endpoints")
					.withUri(discoveryEndpointUri)
					.withStatusCode(ex.getStatusCode().value())
					.withResponseBody(ex.getResponseBodyAsString())
					.build();
		}
	}

}
