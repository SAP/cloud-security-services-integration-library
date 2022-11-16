/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import java.net.URI;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Service that targets Identity service (xsuaa and identity) to request Json
 * Web Keys.
 */
public interface OAuth2TokenKeyService {

	/**
	 * Same as {@link #retrieveTokenKeys(URI, String)} except that zoneId is set to
	 * {@code null}.
	 *
	 * @deprecated gets removed in favor of {@link #retrieveTokenKeys(URI, String)}
	 *             with next major version 3.0.0
	 */
	@Deprecated
	default String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri) throws OAuth2ServiceException {
		throw new UnsupportedOperationException(
				"for security reason this internal method was replaced with retrieveTokenKeys(<jwks_url>, <zone_uuid>)");
	}

	/**
	 * Requests token web key set from OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI (jku).
	 * @param zoneId
	 *            the zone uuid of the tenant. Obligatory parameter in context of
	 *            multi-tenant IAS applications to make sure that the zone uuid
	 *            belongs to the IAS tenant.
	 * @return An endpoint which returns the list of JSON Web Token (JWT) keys as
	 *         JSON string.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String zoneId) throws OAuth2ServiceException;
}
