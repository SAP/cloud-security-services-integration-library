/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.*;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.AUTHORITIES;
import static com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants.SCOPE;
import static com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlowsUtils.buildAdditionalAuthoritiesJson;

/**
 * A client credentials flow builder class. Applications retrieve an instance of
 * this builder from {@link XsuaaTokenFlows} and then create the flow request
 * using a builder pattern.
 */
public class ClientCredentialsTokenFlow {
	private final OAuth2TokenService tokenService;
	private final OAuth2ServiceEndpointsProvider endpointsProvider;
	private final ClientIdentity clientIdentity;
	private boolean disableCache = false;
	private List<String> scopes = new ArrayList<>();
	private String subdomain;
	private String zoneId;
	private Map<String, String> authzAttributes;

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
	ClientCredentialsTokenFlow(OAuth2TokenService tokenService, OAuth2ServiceEndpointsProvider endpointsProvider,
			ClientIdentity clientIdentity) {
		assertNotNull(tokenService, "OAuth2TokenService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null.");
		assertNotNull(clientIdentity, "ClientIdentity must not be null.");
		
		this.tokenService = tokenService;
		this.endpointsProvider = endpointsProvider;
		this.clientIdentity = clientIdentity;
	}

	/**
	 * Adds additional authorization attributes to the request. <br>
	 * Clients can use this to request additional attributes in the
	 * {@code 'az_attr'} claim of the returned token.
	 *
	 * @param additionalAuthorizationAttributes
	 *            - the additional attributes.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow attributes(Map<String, String> additionalAuthorizationAttributes) {
		this.authzAttributes = additionalAuthorizationAttributes;
		return this;
	}

	/**
	 * Sets the subdomain (tenant) the token is requested for.<br>
	 *
	 * @param subdomain
	 *            - the subdomain.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow subdomain(String subdomain) {
		this.subdomain = subdomain;
		return this;
	}

	/**
	 * Sets the zone Id of the tenant<br>
	 *
	 * @param zoneId
	 *            - the zoneId.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow zoneId(String zoneId) {
		this.zoneId = zoneId;
		return this;
	}

	/**
	 * Sets the scope attribute for the token request. This will restrict the scope
	 * of the created token to the scopes provided. By default the scope is not
	 * restricted and the created token contains all granted scopes.
	 * <br>
	 * If you specify a scope that is not authorized for the client, the token
	 * request will fail.
	 *
	 * @param scopes
	 *            - one or many scopes as string.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow scopes(@Nonnull String... scopes) {
		Assertions.assertNotNull(scopes, "Scopes must not be null!");
		this.scopes = Arrays.asList(scopes);
		return this;
	}

	/**
	 * Can be used to disable the cache for the flow.
	 * 
	 * @param disableCache
	 *            - disables cache when set to {@code true}.
	 * @return this builder.
	 */
	public ClientCredentialsTokenFlow disableCache(boolean disableCache) {
		this.disableCache = disableCache;
		return this;
	}

	/**
	 * Executes the token flow and returns a JWT token from XSUAA.
	 *
	 * @return the encoded OAuth access token returned by XSUAA.
	 * @throws IllegalArgumentException
	 *             - in case not all mandatory fields of the token flow request have
	 *             been set.
	 * @throws TokenFlowException
	 *             - in case of an error during the flow, or when the token cannot
	 *             be refreshed.
	 */
	@Nullable
	public OAuth2TokenResponse execute() throws IllegalArgumentException, TokenFlowException {
		Map<String, String> requestParameter = new HashMap<>();
		String authorities = buildAdditionalAuthoritiesJson(authzAttributes);

		if (authorities != null) {
			requestParameter.put(AUTHORITIES, authorities); // places JSON inside the URI
		}
		String scopesParameter = String.join(" ", scopes);
		if (!scopesParameter.isEmpty()) {
			requestParameter.put(SCOPE, scopesParameter);
		}
		try {
			return tokenService
					.retrieveAccessTokenViaClientCredentialsGrant(endpointsProvider.getTokenEndpoint(),
							clientIdentity,
							zoneId, subdomain, requestParameter, disableCache);
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					String.format("Error requesting technical user token with grant_type 'client_credentials': %s",
							e.getMessage()),
					e);
		}
	}

}
