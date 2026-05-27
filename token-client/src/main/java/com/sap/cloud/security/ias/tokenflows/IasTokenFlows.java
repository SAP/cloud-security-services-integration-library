/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.Serial;
import java.io.Serializable;
import java.net.URI;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * Entry point for IAS (Identity Authentication Service) token flows.
 * <p>
 * Provides builder objects for executing OAuth2 token flows against IAS:
 * <ul>
 *   <li>{@link #clientCredentialsTokenFlow()} - for technical user / service-to-service tokens</li>
 *   <li>{@link #jwtBearerTokenFlow()} - for user token exchange (user propagation)</li>
 * </ul>
 *
 * <p>Example usage:
 * <pre>{@code
 * IasTokenFlows tokenFlows = new IasTokenFlows(
 *     tokenService,
 *     iasServiceConfig.getUrl(),
 *     iasServiceConfig.getClientIdentity());
 *
 * // Technical user token
 * OAuth2TokenResponse response = tokenFlows.clientCredentialsTokenFlow()
 *     .appTid(subscriberTenantId)
 *     .resource("target-application")
 *     .execute();
 *
 * // User propagation
 * OAuth2TokenResponse response = tokenFlows.jwtBearerTokenFlow()
 *     .token(incomingJwt)
 *     .resource("target-application")
 *     .execute();
 * }</pre>
 */
public class IasTokenFlows implements Serializable {

	@Serial
	private static final long serialVersionUID = 1L;

	private final transient OAuth2TokenService tokenService;
	private final IasDefaultEndpoints endpointsProvider;
	private final ClientIdentity clientIdentity;
	private final transient IasTenantHostResolver tenantHostResolver;

	/**
	 * Creates a new IasTokenFlows instance.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service for executing HTTP token requests
	 * @param endpointsProvider
	 * 		the IAS endpoints provider
	 * @param clientIdentity
	 * 		the client identity (client ID + secret or certificate)
	 */
	public IasTokenFlows(@Nonnull OAuth2TokenService tokenService,
			@Nonnull IasDefaultEndpoints endpointsProvider,
			@Nonnull ClientIdentity clientIdentity) {
		this(tokenService, endpointsProvider, clientIdentity, null);
	}

	/**
	 * Creates a new IasTokenFlows instance with BTP tenant host resolution support.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service for executing HTTP token requests
	 * @param endpointsProvider
	 * 		the IAS endpoints provider
	 * @param clientIdentity
	 * 		the client identity (client ID + secret or certificate)
	 * @param tenantHostResolver
	 * 		optional resolver for dynamic subscriber subdomain lookup
	 */
	public IasTokenFlows(@Nonnull OAuth2TokenService tokenService,
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
	 * Convenience factory: creates IasTokenFlows from an {@link OAuth2ServiceConfiguration}.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service
	 * @param config
	 * 		the IAS service configuration (from service binding)
	 * @return configured IasTokenFlows instance
	 */
	public static IasTokenFlows fromConfiguration(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceConfiguration config) {
		assertNotNull(config, "OAuth2ServiceConfiguration must not be null.");
		return new IasTokenFlows(tokenService, new IasDefaultEndpoints(config), config.getClientIdentity());
	}

	/**
	 * Convenience factory: creates IasTokenFlows with tenant host resolution enabled.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service
	 * @param config
	 * 		the IAS service configuration (from service binding)
	 * @param btpTenantApiBaseUri
	 * 		the BTP tenant API base URI for subdomain resolution
	 * @param httpClient
	 * 		the HTTP client for tenant API requests
	 * @return configured IasTokenFlows instance with tenant resolution
	 */
	public static IasTokenFlows fromConfiguration(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceConfiguration config,
			@Nonnull URI btpTenantApiBaseUri,
			@Nonnull SecurityHttpClient httpClient) {
		assertNotNull(config, "OAuth2ServiceConfiguration must not be null.");
		IasTenantHostResolver resolver = new IasTenantHostResolver(btpTenantApiBaseUri, httpClient);
		return new IasTokenFlows(tokenService, new IasDefaultEndpoints(config), config.getClientIdentity(), resolver);
	}

	/**
	 * Creates a new Client Credentials Token Flow builder for IAS.
	 * <p>
	 * Use this to request technical user tokens for service-to-service communication.
	 *
	 * @return the {@link IasClientCredentialsTokenFlow} builder
	 */
	public IasClientCredentialsTokenFlow clientCredentialsTokenFlow() {
		return new IasClientCredentialsTokenFlow(tokenService, endpointsProvider, clientIdentity, tenantHostResolver);
	}

	/**
	 * Creates a new JWT Bearer Token Flow builder for IAS.
	 * <p>
	 * Use this to exchange a user token for a new token (user propagation).
	 *
	 * @return the {@link IasJwtBearerTokenFlow} builder
	 */
	public IasJwtBearerTokenFlow jwtBearerTokenFlow() {
		return new IasJwtBearerTokenFlow(tokenService, endpointsProvider, clientIdentity, tenantHostResolver);
	}
}
