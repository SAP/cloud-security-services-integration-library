package com.sap.cloud.security.xsuaa.backend;

import java.net.URI;
import java.util.Map;
import java.util.Optional;

/**
 * Retrieves OAuth2 Access Tokens as documented here:
 * https://docs.cloudfoundry.org/api/uaa/version/4.31.0/index.html#token
 */
public interface OAuth2TokenService {

	/**
	 * Requests access token from OAuth Server with client credentials.
	 *
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientCredentials
	 *            the client id and secret of the OAuth client, the recipient of the
	 *            token.
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 *
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2AccessToken retrieveAccessTokenViaClientCredentialsGrant(URI tokenEndpointUri,
			ClientCredentials clientCredentials,
			Optional<Map<String, String>> optionalParameters) throws OAuth2ServiceException;

	/**
	 * Exchanges user access token from OAuth Server with user access token. This
	 * endpoint returns only opaque access token, so that another call using {link
	 * #retrieveAccessTokenViaRefreshToken} is required.
	 *
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientCredentials
	 *            the client id and secret of the OAuth client, the recipient of the
	 *            token.
	 * @param token
	 *            the user bearer token, that represents an authenticated user that
	 *            has must have uaa.user scope.
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 *
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 * @deprecated instead use jwt bearer.
	 */
	@Deprecated
	OAuth2AccessToken retrieveAccessTokenViaUserTokenGrant(URI tokenEndpointUri,
			ClientCredentials clientCredentials, String token, Optional<Map<String, String>> optionalParameters)
			throws OAuth2ServiceException;

	/**
	 * Requests access token from OAuth Server with refresh-token
	 *
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientCredentials
	 *            the client id and secret of the OAuth client, the recipient of the
	 *            token.
	 * @param refreshToken
	 *            the refresh token that was returned along with the access token
	 *            {link #OAuth2AccessToken}.
	 *
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2AccessToken retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri, ClientCredentials clientCredentials,
			String refreshToken) throws OAuth2ServiceException;
}
