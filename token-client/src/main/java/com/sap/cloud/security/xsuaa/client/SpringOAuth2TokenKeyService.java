package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.Assertions;
import org.springframework.http.*;
import org.springframework.web.client.*;

import javax.annotation.Nonnull;
import java.net.URI;
import java.util.Collections;

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
			// create headers
			HttpHeaders headers = new HttpHeaders();
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
			headers.set(HEADER_ZONE_ID, zoneId != null ? zoneId : "");
			HttpEntity request = new HttpEntity(headers);

			ResponseEntity<String> response = restOperations.exchange(
					tokenKeysEndpointUri,
					HttpMethod.GET,
					request,
					String.class
			);

			if (HttpStatus.OK.value() == response.getStatusCode().value()) {
				return response.getBody();
			} else {
				throw OAuth2ServiceException.builder("Error retrieving token keys")
						.withUri(tokenKeysEndpointUri)
						.withStatusCode(response.getStatusCodeValue())
						.withResponseBody(response.getBody())
						.build();
			}
		} catch(HttpStatusCodeException error) {
			throw OAuth2ServiceException.builder("Error retrieving token keys")
					.withUri(tokenKeysEndpointUri)
					.withStatusCode(error.getStatusCode().value())
					.build();
		} catch (Exception ex) {
			throw OAuth2ServiceException.builder("Unexpected error retrieving token keys: " + ex.getMessage())
					.withUri(tokenKeysEndpointUri)
					.build();
		}
	}

}
