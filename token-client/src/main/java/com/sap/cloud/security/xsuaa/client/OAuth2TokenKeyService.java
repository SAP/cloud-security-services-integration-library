package com.sap.cloud.security.xsuaa.client;

import java.net.URI;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface OAuth2TokenKeyService {
	public static final String HEADER_ZONE_ID = "X-Identity-Zone-Id";

	/**
	 * Requests token web key set from OAuth Server.
	 *
	 * @param tokenKeysEndpointUri
	 *            the token endpoint URI (jku).
	 * @param zoneId
	 *            the zone identifier.
	 * @return An endpoint which returns the list of JSON Web Token (JWT) keys as
	 *         JSON string.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri, @Nullable String zoneId) throws OAuth2ServiceException;


	/**
	 * Same as {@link #retrieveTokenKeys(URI, String)} except that zoneId is set to {@code null}.
	 * @deprecated gets removed in favor of {@link #retrieveTokenKeys(URI, String)}
	 * with next major version 3.0.0
	 */
	@Deprecated
	default String retrieveTokenKeys(@Nonnull URI tokenKeysEndpointUri) throws OAuth2ServiceException {
		return retrieveTokenKeys(tokenKeysEndpointUri, null);
	}
}
