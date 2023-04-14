/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientIdentity;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;

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
	 * @param clientIdentity
	 *            the client identity of the OAuth client, the recipient of the
	 *            token.
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 * @param disableCacheForRequest
	 *            set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 *
	 * @deprecated gets removed in favor of
	 *             {@link #retrieveAccessTokenViaClientCredentialsGrant(URI, ClientIdentity, String, String, Map, boolean)}
	 *             with next major version 3.0.0
	 */
	@Deprecated
	default OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientIdentity clientIdentity,
			@Nullable String subdomain, @Nullable Map<String, String> optionalParameters,
			boolean disableCacheForRequest)
			throws OAuth2ServiceException {
		return retrieveAccessTokenViaClientCredentialsGrant(tokenEndpointUri, clientIdentity, null, subdomain,
				optionalParameters, disableCacheForRequest);
	}

	/**
	 * Requests access token from OAuth Server with client credentials.
	 *
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientIdentity
	 *            the client identity of the OAuth client, the recipient of the
	 *            token.
	 * @param zoneId
	 *            Zone identifier - tenant discriminator
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 * @param disableCacheForRequest
	 *            set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientIdentity clientIdentity,
			@Nullable String zoneId,
			@Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters,
			boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * Same as
	 * {@link #retrieveAccessTokenViaClientCredentialsGrant(URI, ClientIdentity, String, Map, boolean)}
	 * except that disableCacheForRequest is set to {@code false}.
	 * 
	 * @deprecated gets removed in favor of
	 *             {@link #retrieveAccessTokenViaClientCredentialsGrant(URI, ClientIdentity, String, Map, boolean)}
	 *             with next major version 3.0.0
	 */
	@Deprecated
	default OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {
		return retrieveAccessTokenViaClientCredentialsGrant(tokenEndpointUri, clientIdentity, subdomain,
				optionalParameters, false);
	}

	/**
	 * Exchanges user access token from OAuth Server with user access token. This
	 * endpoint returns only opaque access token, so that another call using {link
	 * #retrieveAccessTokenViaRefreshToken} is required.
	 *
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientIdentity
	 *            the client identity of the OAuth client, the recipient of the
	 *            token.
	 * @param token
	 *            the user bearer token, that represents an authenticated user.
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 * @deprecated instead use jwt bearer
	 *             {{@link #retrieveAccessTokenViaJwtBearerTokenGrant(URI, ClientIdentity, String, String, Map)}}.
	 */
	@Deprecated
	OAuth2TokenResponse retrieveAccessTokenViaUserTokenGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters)
			throws OAuth2ServiceException;

	/**
	 * Requests access token from OAuth Server with refresh-token.
	 *
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientIdentity
	 *            the client identity of the OAuth client, the recipient of the
	 *            token.
	 * @param refreshToken
	 *            the refresh token that was returned along with the access token
	 *            {link #OAuth2AccessToken}.
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param disableCacheForRequest
	 *            set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri, ClientIdentity clientIdentity,
			String refreshToken, @Nullable String subdomain, boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * Same as
	 * {@link #retrieveAccessTokenViaRefreshToken(URI, ClientIdentity, String, String, boolean)}
	 * except that disableCacheForRequest is set to {@code false}.
	 * 
	 * @deprecated gets removed in favor of
	 *             {@link #retrieveAccessTokenViaRefreshToken(URI, ClientIdentity, String, String, boolean)}
	 *             with next major version 3.0.0
	 */
	@Deprecated
	default OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri,
			ClientIdentity clientIdentity,
			String refreshToken, @Nullable String subdomain) throws OAuth2ServiceException {
		return retrieveAccessTokenViaRefreshToken(tokenEndpointUri, clientIdentity, refreshToken, subdomain, false);
	}

	/**
	 * Requests access token from OAuth Server with user / password.
	 *
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientIdentity
	 *            the client identity of the OAuth client, the recipient of the
	 *            token.
	 * @param username
	 *            the username for the user trying to get a token
	 * @param password
	 *            the password for the user trying to get a token
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 * @param disableCacheForRequest
	 *            set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(URI tokenEndpointUri, ClientIdentity clientIdentity,
			String username, String password, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * Same as
	 * {@link #retrieveAccessTokenViaPasswordGrant(URI, ClientIdentity, String, String, String, Map, boolean)}
	 * except that disableCacheForRequest is set to {@code false}.
	 * 
	 * @deprecated gets removed in favor of
	 *             {@link #retrieveAccessTokenViaPasswordGrant(URI, ClientIdentity, String, String, String, Map, boolean)}
	 *             with next major version 3.0.0
	 */
	@Deprecated
	default OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity,
			String username, String password, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {
		return retrieveAccessTokenViaPasswordGrant(tokenEndpointUri, clientIdentity, username, password, subdomain,
				optionalParameters, false);
	}

	/**
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientIdentity
	 *            the client identity of the OAuth client, the recipient of the
	 *            token.
	 * @param token
	 *            the JWT token identifying representing the user to be
	 *            authenticated
	 * @param subdomain
	 *            optionally indicates what Identity Zone this request goes to by
	 *            supplying a subdomain (tenant).
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 * @param disableCacheForRequest
	 *            set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * Same as
	 * {@link #retrieveAccessTokenViaJwtBearerTokenGrant(URI, ClientIdentity, String, String, Map, boolean)}
	 * except that disableCacheForRequest is set to {@code false}.
	 * 
	 * @deprecated gets removed in favor of
	 *             {@link #retrieveAccessTokenViaJwtBearerTokenGrant(URI, ClientIdentity, String, String, Map, boolean)}
	 *             with next major version 3.0.0
	 */
	@Deprecated
	default OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters) throws OAuth2ServiceException {
		return retrieveAccessTokenViaJwtBearerTokenGrant(tokenEndpointUri, clientIdentity, token, subdomain,
				optionalParameters, false);
	}

	/**
	 * @param tokenEndpointUri
	 *            the token endpoint URI.
	 * @param clientIdentity
	 *            the client identity of the OAuth client, the recipient of the
	 *            token.
	 * @param token
	 *            the JWT token identifying representing the user to be
	 *            authenticated
	 * @param optionalParameters
	 *            optional request parameters, can be null.
	 * @param disableCache
	 *            setting to true disables the token cache for this request.
	 * @param xZid
	 *            zone id of the tenant
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 *             in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity,
			@Nonnull String token,
			@Nullable Map<String, String> optionalParameters,
			boolean disableCache,
			@Nonnull String xZid) throws OAuth2ServiceException;
}
