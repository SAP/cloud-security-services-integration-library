package com.sap.cloud.security.xsuaa.client;

import java.net.URI;

import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;

import javax.annotation.Nonnull;

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
	JSONWebKeySet retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri) throws OAuth2ServiceException;
}
