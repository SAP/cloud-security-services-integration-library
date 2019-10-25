package com.sap.cloud.security.token.client;

import java.net.URI;

import com.sap.cloud.security.token.jwt.JSONWebKeySet;

public interface OAuth2TokenKeyService {

	/**
	 * Requests token web key set from OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI.
	 * @return the JSON Web key set.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	JSONWebKeySet retrieveTokenKeys(URI tokenKeysEndpointUri) throws OAuth2ServiceException;
}
