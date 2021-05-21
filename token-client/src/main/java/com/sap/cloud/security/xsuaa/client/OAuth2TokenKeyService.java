/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import java.net.URI;
import javax.annotation.Nonnull;

public interface OAuth2TokenKeyService {

	/**
	 * Requests token web key set from OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI (jku).
	 * @return An endpoint which returns the list of JSON Web Token (JWT) keys as
	 *         JSON string.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 * @deprecated replace with {@link #retrieveTokenKeys(URI, String)}
	 */
	@Deprecated
	default String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri) throws OAuth2ServiceException {
		return retrieveTokenKeys(tokenKeysEndpointUri, null);
	}

	/**
	 * Requests token web key set from OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI (jku).
	 * @param zoneId
	 * 			  the zone uuid of the tenant.
	 * 			  Obligatory parameter in context of multi-tenant IAS applications to make sure
	 * 			  that the zone uuid belongs to the IAS tenant.
	 * @return An endpoint which returns the list of JSON Web Token (JWT) keys as
	 *         JSON string.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, String zoneId) throws OAuth2ServiceException;
}
