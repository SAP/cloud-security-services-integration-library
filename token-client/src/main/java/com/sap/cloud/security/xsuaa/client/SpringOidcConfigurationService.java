package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;

import java.net.URI;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
			ResponseEntity<String> response = restOperations.getForEntity(discoveryEndpointUri, String.class);
			if (HttpStatus.OK.value() == response.getStatusCode().value()) {
				return new DefaultOidcConfigurationService.OidcEndpointsProvider(response.getBody());
			} else {
				throw OAuth2ServiceException.createWithStatusCodeAndResponseBody(
						"Error retrieving configured oidc endpoints",
						response.getStatusCodeValue(), response.getBody());
			}
		} catch (HttpClientErrorException ex) {
			throw OAuth2ServiceException.createWithStatusCodeAndResponseBody(
					"Error retrieving configured oidc endpoints",
					ex.getStatusCode().value(), ex.getResponseBodyAsString());
		}
	}

}
