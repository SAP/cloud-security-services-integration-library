/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;

/**
 * Service that targets Identity service (xsuaa and identity) to request Json
 * Web Keys.
 */
public interface OAuth2TokenKeyService {

	/**
	 * Requests token web key set from Xsuaa OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI (jku).
	 * @param tenantId
	 *            the unique identifier of the tenant. Obligatory parameter in context of
	 *            multi-tenant IAS applications to make sure that the tenant id
	 *            belongs to the IAS tenant.
	 * @return list of JSON Web Token (JWT) keys as
	 *         JSON string.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String tenantId) throws OAuth2ServiceException;

	/**
	 * Requests token web key set from IAS OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI (jku).
	 * @param tenantId
	 *            the unique identifier of the tenant. Obligatory parameter in context of
	 *            multi-tenant IAS applications to make sure that the tenant id
	 *            belongs to the IAS tenant.
	 * @param clientId
	 * 				clientId from the service binding
	 * @return list of JSON Web Token (JWT) keys as
	 *         JSON string.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	default String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String tenantId, @Nullable String clientId) throws OAuth2ServiceException {
		return retrieveTokenKeys(tokenKeysEndpointUri, tenantId);
	}

	/**
	 * Requests token web key set from IAS OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI (jku).
	 * @param tenantId
	 *            the unique identifier of the tenant. Obligatory parameter in context of
	 *            multi-tenant IAS applications to make sure that the tenant id
	 *            belongs to the IAS tenant.
	 * @param clientId
	 * 				clientId from the service binding
	 * @param azp
	 * 				azp from token
	 * @return list of JSON Web Token (JWT) keys as
	 *         JSON string.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	default String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String tenantId, @Nullable String clientId, @Nullable String azp) throws OAuth2ServiceException {
		return retrieveTokenKeys(tokenKeysEndpointUri, tenantId);
	}
}
