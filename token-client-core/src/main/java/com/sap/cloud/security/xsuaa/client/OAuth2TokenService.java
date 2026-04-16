/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.ClientIdentity;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.Map;

/**
 * Retrieves OAuth2 Access Tokens as documented on <a href=
 * "https://docs.cloudfoundry.org/api/uaa/version/74.1.0/index.html#token">Cloud Foundry UAA</a>.<br> Note that the
 * XSUAA API might differ slightly from these specs which is why not all parameters from the Cloud Foundry UAA
 * documentation are configurable via this library.
 */
public interface OAuth2TokenService {

	/**
	 * Requests access token from OAuth Server with client credentials.
	 *
	 * @param tokenEndpointUri
	 * 		the token endpoint URI.
	 * @param clientIdentity
	 * 		the client identity of the OAuth client, the recipient of the token.
	 * @param zoneId
	 * 		Zone identifier - tenant discriminator
	 * @param subdomain
	 * 		optionally indicates what Identity Zone this request goes to by supplying a subdomain (tenant).
	 * @param optionalParameters
	 * 		optional request parameters, can be null.
	 * @param disableCacheForRequest
	 * 		set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken.
	 * @throws OAuth2ServiceException
	 * 		in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaClientCredentialsGrant(@Nonnull URI tokenEndpointUri,
			@Nonnull ClientIdentity clientIdentity,
			@Nullable String zoneId,
			@Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters,
			boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * Requests access token from OAuth Server with refresh-token.
	 *
	 * @param tokenEndpointUri
	 * 		the token endpoint URI.
	 * @param clientIdentity
	 * 		the client identity of the OAuth client, the recipient of the token.
	 * @param refreshToken
	 * 		the refresh token that was returned along with the access token {link #OAuth2AccessToken}.
	 * @param subdomain
	 * 		optionally indicates what Identity Zone this request goes to by supplying a subdomain (tenant).
	 * @param disableCacheForRequest
	 * 		set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 * 		in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaRefreshToken(URI tokenEndpointUri, ClientIdentity clientIdentity,
			String refreshToken, @Nullable String subdomain, boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * Requests access token from OAuth Server with user / password.
	 *
	 * @param tokenEndpointUri
	 * 		the token endpoint URI.
	 * @param clientIdentity
	 * 		the client identity of the OAuth client, the recipient of the token.
	 * @param username
	 * 		the username for the user trying to get a token
	 * @param password
	 * 		the password for the user trying to get a token
	 * @param subdomain
	 * 		optionally indicates what Identity Zone this request goes to by supplying a subdomain (tenant).
	 * @param optionalParameters
	 * 		optional request parameters, can be null.
	 * @param disableCacheForRequest
	 * 		set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 * 		in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaPasswordGrant(URI tokenEndpointUri, ClientIdentity clientIdentity,
			String username, String password, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * @param tokenEndpointUri
	 * 		the token endpoint URI.
	 * @param clientIdentity
	 * 		the client identity of the OAuth client, the recipient of the token.
	 * @param token
	 * 		the JWT token identifying representing the user to be authenticated
	 * @param subdomain
	 * 		optionally indicates what Identity Zone this request goes to by supplying a subdomain (tenant).
	 * @param optionalParameters
	 * 		optional request parameters, can be null.
	 * @param disableCacheForRequest
	 * 		set to true disables the token cache for this request.
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 * 		in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity, String token, @Nullable String subdomain,
			@Nullable Map<String, String> optionalParameters, boolean disableCacheForRequest)
			throws OAuth2ServiceException;

	/**
	 * @param tokenEndpointUri
	 * 		the token endpoint URI.
	 * @param clientIdentity
	 * 		the client identity of the OAuth client, the recipient of the token.
	 * @param token
	 * 		the JWT token identifying representing the user to be authenticated
	 * @param optionalParameters
	 * 		optional request parameters, can be null.
	 * @param disableCache
	 * 		setting to true disables the token cache for this request.
	 * @param xZid
	 * 		zone id of the tenant
	 * @return the OAuth2AccessToken
	 * @throws OAuth2ServiceException
	 * 		in case of an error during the http request.
	 */
	OAuth2TokenResponse retrieveAccessTokenViaJwtBearerTokenGrant(URI tokenEndpointUri,
			ClientIdentity clientIdentity,
			@Nonnull String token,
			@Nullable Map<String, String> optionalParameters,
			boolean disableCache,
			@Nonnull String xZid) throws OAuth2ServiceException;
}
