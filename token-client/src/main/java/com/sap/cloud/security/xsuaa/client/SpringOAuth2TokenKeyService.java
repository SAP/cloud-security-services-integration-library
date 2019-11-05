package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySet;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeySetFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import javax.annotation.Nonnull;
import java.net.URI;

public class SpringOAuth2TokenKeyService implements OAuth2TokenKeyService {
	private final RestOperations restOperations;

	public SpringOAuth2TokenKeyService(@Nonnull RestOperations restOperations) {
		Assertions.assertNotNull(restOperations, "restOperations must not be null!");
		this.restOperations = restOperations;
	}

	@Override
	public JsonWebKeySet retrieveTokenKeys(URI tokenKeysEndpointUri) throws OAuth2ServiceException {
		Assertions.assertNotNull(tokenKeysEndpointUri, "Token key endpoint must not be null!");
		try {
			// TODO 30.10.19 c5295400: See if that even works?
			ResponseEntity<String> response = restOperations.getForEntity(tokenKeysEndpointUri, String.class);
			if (HttpStatus.OK.value() == response.getStatusCode().value()) {
				return JsonWebKeySetFactory.createFromJSON(response.getBody());
			} else {
				throw OAuth2ServiceException.createWithStatusCodeAndResponseBody("Error retrieving token keys",
						response.getStatusCodeValue(), response.getBody());
			}
		} catch (HttpClientErrorException ex) {
			throw OAuth2ServiceException.createWithStatusCodeAndResponseBody("Error retrieving token keys",
					ex.getStatusCode().value(), ex.getResponseBodyAsString());
		}
	}

}
