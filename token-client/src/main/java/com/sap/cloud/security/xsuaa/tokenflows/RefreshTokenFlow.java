/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.xsa.security.container.XSTokenRequest;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * A refresh token flow builder. <br>
 * Applications can use this flow exchange a given refresh token for a
 * (refreshed) JWT token.
 */
public class RefreshTokenFlow {

	private final XsuaaTokenFlowRequest request;
	private String refreshToken;
	private final OAuth2TokenService tokenService;
	private boolean disableCache = false;

	/**
	 * Creates a new instance.
	 *
	 * @param tokenService
	 *            - the {@link OAuth2TokenService} used to execute the final
	 *            request.
	 * @param endpointsProvider
	 *            - the endpoints provider
	 * @param clientIdentity
	 *            - the OAuth client identity
	 */
	RefreshTokenFlow(OAuth2TokenService tokenService, OAuth2ServiceEndpointsProvider endpointsProvider,
			ClientIdentity clientIdentity) {
		assertNotNull(tokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");
		assertNotNull(clientIdentity, "ClientIdentity must not be null.");

		this.tokenService = tokenService;
		this.request = new XsuaaTokenFlowRequest(endpointsProvider.getTokenEndpoint());
		this.request.setClientIdentity(clientIdentity);
	}

	/**
	 * Sets the subdomain (tenant) the token is requested for.<br>
	 *
	 * @param subdomain
	 *            - the subdomain.
	 * @return this builder.
	 */
	public RefreshTokenFlow subdomain(String subdomain) {
		request.setSubdomain(subdomain);
		return this;
	}

	/**
	 * Sets the mandatory refresh token to be exchanged for a (refreshed) JWT.
	 * 
	 * @param refreshToken
	 *            - the refresh token to be exchanged for a JWT.
	 * @return this builder object.
	 */
	public RefreshTokenFlow refreshToken(String refreshToken) {
		assertNotNull(refreshToken, "RefreshToken must not be null.");
		this.refreshToken = refreshToken;
		return this;
	}

	/**
	 * Can be used to disable the cache for the flow.
	 *
	 * @param disableCache
	 *            - disables cache when set to {@code true}.
	 * @return this builder.
	 */
	public RefreshTokenFlow disableCache(boolean disableCache) {
		this.disableCache = disableCache;
		return this;
	}

	/**
	 * Executes the refresh token flow against XSUAA.
	 * 
	 * @return the refreshed OAuth access token returned by XSUAA or an exception in
	 *         case the token could not be refreshed.
	 * @throws IllegalStateException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws IllegalArgumentException
	 *             - in case the refresh token flow request is not valid.
	 * @throws TokenFlowException
	 *             - in case of an error during the flow, or when the token cannot
	 *             be refreshed.
	 */
	public OAuth2TokenResponse execute() throws IllegalStateException, IllegalArgumentException, TokenFlowException {
		checkRequest(request);

		return refreshToken(refreshToken, request);
	}

	/**
	 * Checks that all mandatory fields of the token flow request have been set.
	 * Otherwise throws an exception.
	 * 
	 * @param request
	 *            - the request to check.
	 * @throws IllegalStateException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws IllegalArgumentException
	 *             - in case the refresh token flow request is not valid.
	 */
	private void checkRequest(XSTokenRequest request) throws IllegalStateException, IllegalArgumentException {
		if (refreshToken == null) {
			throw new IllegalStateException(
					"Refresh token not set. Make sure to have called the refreshToken() method on RefreshTokenFlow builder.");
		}

		if (!request.isValid()) {
			throw new IllegalArgumentException(
					"Refresh token flow request is not valid. Make sure all mandatory fields are set.");
		}
	}

	/**
	 * Refreshes the token based on the given {@code refreshToken} instance.
	 * 
	 * @param refreshToken
	 *            - the (opaque) refresh token.
	 * @param request
	 *            - the token flow request to execute.
	 * @return the encoded OAuth access token received in exchange for the refresh
	 *         token.
	 * @throws TokenFlowException
	 *             - in case of an error in the flow.
	 */
	private OAuth2TokenResponse refreshToken(String refreshToken, XsuaaTokenFlowRequest request)
			throws TokenFlowException {
		try {
			return tokenService.retrieveAccessTokenViaRefreshToken(
					request.getTokenEndpoint(),
					request.getClientIdentity(), refreshToken,
					request.getSubdomain(), disableCache);
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error refreshing token with grant_type 'refresh_token': %s", e.getMessage()), e);
		}
	}
}
