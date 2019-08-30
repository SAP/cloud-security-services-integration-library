package com.sap.cloud.security.xsuaa.client;

import java.net.URI;
import java.util.Map;

import org.springframework.lang.Nullable;

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
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 *
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(URI tokenEndpointUri,
			ClientCredentials clientCredentials, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException;

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
	 *            must have uaa.user scope.
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 *
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 * @deprecated instead use jwt bearer.
	 */
	@Deprecated
	OAuth2TokenResponse retrieveAccessTokenViaUserTokenGrant(URI tokenEndpointUri,
			ClientCredentials clientCredentials, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters)
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
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri, ClientCredentials clientCredentials,
			String refreshToken, @Nullable String subdomain) throws OAuth2ServiceException;
}
