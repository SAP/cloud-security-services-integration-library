/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p> 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.*;
import com.sap.cloud.security.config.ClientIdentity;

import javax.annotation.Nonnull;
import java.util.Map;

public class PasswordTokenFlow {
	private final OAuth2TokenService tokenService;
	private final OAuth2ServiceEndpointsProvider endpointsProvider;
	private final ClientIdentity clientIdentity;
	private String username;
	private String password;
	private String subdomain;
	private Map<String, String> optionalParameters;
	private boolean disableCache = false;

	public PasswordTokenFlow(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceEndpointsProvider endpointsProvider,
			@Nonnull ClientIdentity clientIdentity) {
		Assertions.assertNotNull(tokenService, "OAuth2TokenService must not be null!");
		Assertions.assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null!");
		Assertions.assertNotNull(clientIdentity, "ClientIdentity must not be null!");
		this.tokenService = tokenService;
		this.endpointsProvider = endpointsProvider;
		this.clientIdentity = clientIdentity;
	}

	/**
	 * Executes this flow against the XSUAA endpoint. As a result the exchanged JWT
	 * token is returned.
	 *
	 * @return the JWT instance returned by XSUAA.
	 * @throws IllegalStateException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws TokenFlowException
	 *             - in case of an error during the flow, or when the token cannot
	 *             be obtained.
	 */
	public OAuth2TokenResponse execute() throws TokenFlowException {
		checkParameter(username, "Username must be set!");
		checkParameter(password, "Password must be set!");
		try {
			return tokenService
					.retrieveAccessTokenViaPasswordGrant(endpointsProvider.getTokenEndpoint(), clientIdentity,
							username, password, subdomain, optionalParameters, disableCache);
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error requesting user token with grant_type '%s': %s",
							OAuth2TokenServiceConstants.GRANT_TYPE_PASSWORD, e.getMessage()),
					e);
		}
	}

	/**
	 * The password for the user trying to get a token. This is a required
	 * parameter.
	 *
	 * @param password
	 *            - the password.
	 * @return this builder.
	 */
	public PasswordTokenFlow password(String password) {
		this.password = password;
		return this;
	}

	/**
	 * The username for the user trying to get a token. This is a required
	 * parameter.
	 *
	 * @param username
	 *            - the username.
	 * @return this builder.
	 */
	public PasswordTokenFlow username(String username) {
		this.username = username;
		return this;
	}

	/**
	 * Set the Subdomain the token is requested for.
	 *
	 * @param subdomain
	 *            - the subdomain.
	 * @return this builder.
	 */
	public PasswordTokenFlow subdomain(String subdomain) {
		this.subdomain = subdomain;
		return this;
	}

	/**
	 * Adds additional authorization attributes to the request.
	 *
	 * @param optionalParameters
	 *            - the optional parameters.
	 * @return this builder.
	 */
	public PasswordTokenFlow optionalParameters(Map<String, String> optionalParameters) {
		this.optionalParameters = optionalParameters;
		return this;
	}

	/**
	 * Can be used to disable the cache for the flow.
	 *
	 * @param disableCache
	 *            - disables cache when set to {@code true}.
	 * @return this builder.
	 */
	public PasswordTokenFlow disableCache(boolean disableCache) {
		this.disableCache = disableCache;
		return this;
	}

	private void checkParameter(String parameter, String message) {
		if (parameter == null) {
			throw new IllegalStateException(message);
		}
	}
}
