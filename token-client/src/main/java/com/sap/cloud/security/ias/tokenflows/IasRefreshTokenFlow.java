/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A refresh token flow builder for IAS (Identity Authentication Service).
 * <p>
 * Exchanges a previously issued refresh token for a new access token. IAS issues
 * refresh tokens in the OIDC authorization-code flow; this builder lets a backend
 * trade such a refresh token for a fresh access token via {@code grant_type=refresh_token}.
 */
public class IasRefreshTokenFlow {

	private static final Logger LOGGER = LoggerFactory.getLogger(IasRefreshTokenFlow.class);

	private final OAuth2TokenService tokenService;
	private final IasDefaultEndpoints endpointsProvider;
	private final ClientIdentity clientIdentity;
	@Nullable
	private final IasTenantHostResolver tenantHostResolver;

	private String refreshToken;
	private String appTid;
	private boolean disableCache = false;

	IasRefreshTokenFlow(@Nonnull OAuth2TokenService tokenService,
			@Nonnull IasDefaultEndpoints endpointsProvider,
			@Nonnull ClientIdentity clientIdentity,
			@Nullable IasTenantHostResolver tenantHostResolver) {
		assertNotNull(tokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "IasDefaultEndpoints must not be null.");
		assertNotNull(clientIdentity, "ClientIdentity must not be null.");

		this.tokenService = tokenService;
		this.endpointsProvider = endpointsProvider;
		this.clientIdentity = clientIdentity;
		this.tenantHostResolver = tenantHostResolver;
	}

	/**
	 * Sets the mandatory refresh token to be exchanged for a new access token.
	 *
	 * @param refreshToken
	 * 		the refresh token previously issued by IAS
	 * @return this builder.
	 */
	public IasRefreshTokenFlow refreshToken(@Nonnull String refreshToken) {
		assertNotNull(refreshToken, "Refresh token must not be null.");
		this.refreshToken = refreshToken;
		return this;
	}

	/**
	 * Sets the subscriber tenant ID. Triggers subscriber-host resolution if an
	 * {@link IasTenantHostResolver} was wired into the parent {@link IasTokenFlows}.
	 *
	 * @param appTid
	 * 		the subscriber tenant ID
	 * @return this builder.
	 */
	public IasRefreshTokenFlow appTid(@Nonnull String appTid) {
		this.appTid = appTid;
		return this;
	}

	/**
	 * Disables the token cache for this request.
	 *
	 * @param disableCache
	 * 		{@code true} to bypass the cache
	 * @return this builder.
	 */
	public IasRefreshTokenFlow disableCache(boolean disableCache) {
		this.disableCache = disableCache;
		return this;
	}

	/**
	 * Executes the refresh token flow against the IAS token endpoint.
	 *
	 * @return the OAuth2 token response
	 * @throws TokenFlowException
	 * 		if the refresh token is missing or the token request fails
	 */
	@Nonnull
	public OAuth2TokenResponse execute() throws TokenFlowException {
		if (refreshToken == null) {
			throw new IllegalStateException(
					"Refresh token not set. Make sure to have called the refreshToken() method on IasRefreshTokenFlow builder.");
		}

		URI tokenEndpoint = resolveTokenEndpoint();

		try {
			return tokenService.retrieveAccessTokenViaRefreshToken(
					tokenEndpoint,
					clientIdentity,
					refreshToken,
					null,
					disableCache);
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					"Error refreshing IAS token with grant_type 'refresh_token': %s".formatted(e.getMessage()), e);
		}
	}

	private URI resolveTokenEndpoint() throws TokenFlowException {
		if (appTid != null && tenantHostResolver != null) {
			try {
				String subscriberSubdomain = tenantHostResolver.resolve(appTid);
				if (subscriberSubdomain != null) {
					return endpointsProvider.withSubdomain(subscriberSubdomain).getTokenEndpoint();
				}
			} catch (OAuth2ServiceException e) {
				throw new TokenFlowException(
						"Error resolving IAS tenant host for app_tid '%s': %s".formatted(appTid, e.getMessage()), e);
			}
		} else if (appTid != null && tenantHostResolver == null) {
			LOGGER.warn("app_tid '{}' is set but no IasTenantHostResolver is configured. "
					+ "The token request will use the provider endpoint. "
					+ "Ensure the IAS service binding contains the '{}' property for dynamic tenant resolution.",
					appTid, IasTokenFlows.BTP_TENANT_API_PROPERTY);
		}
		return endpointsProvider.getTokenEndpoint();
	}
}