/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpClientProvider;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

	private static final Logger LOGGER = LoggerFactory.getLogger(IasTokenFlows.class);

	/**
	 * The property name in the IAS service binding that holds the BTP tenant API base URI.
	 */
	public static final String BTP_TENANT_API_PROPERTY = "btp-tenant-api";

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
	 * <p>
	 * If the configuration contains a {@value #BTP_TENANT_API_PROPERTY} property,
	 * dynamic tenant host resolution is automatically enabled using the default
	 * {@link SecurityHttpClient} from the {@link SecurityHttpClientProvider}.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service
	 * @param config
	 * 		the IAS service configuration (from service binding)
	 * @return configured IasTokenFlows instance (with tenant resolution if BTP API URI is present)
	 */
	public static IasTokenFlows fromConfiguration(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceConfiguration config) {
		return fromConfiguration(tokenService, config, IasTenantHostCacheConfiguration.defaultConfiguration());
	}

	/**
	 * Convenience factory: creates IasTokenFlows from an {@link OAuth2ServiceConfiguration} with an
	 * explicit cache configuration for tenant host resolution.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service
	 * @param config
	 * 		the IAS service configuration (from service binding)
	 * @param cacheConfiguration
	 * 		cache configuration for the tenant host resolver
	 * @return configured IasTokenFlows instance (with tenant resolution if BTP API URI is present)
	 */
	public static IasTokenFlows fromConfiguration(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceConfiguration config,
			@Nonnull IasTenantHostCacheConfiguration cacheConfiguration) {
		assertNotNull(config, "OAuth2ServiceConfiguration must not be null.");
		assertNotNull(cacheConfiguration, "IasTenantHostCacheConfiguration must not be null.");
		IasTenantHostResolver resolver = createResolverFromConfig(config, null, cacheConfiguration);
		return new IasTokenFlows(tokenService, new IasDefaultEndpoints(config), config.getClientIdentity(), resolver);
	}

	/**
	 * Convenience factory: creates IasTokenFlows with an explicit HTTP client for tenant resolution.
	 * <p>
	 * If the configuration contains a {@value #BTP_TENANT_API_PROPERTY} property,
	 * dynamic tenant host resolution is automatically enabled using the provided HTTP client.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service
	 * @param config
	 * 		the IAS service configuration (from service binding)
	 * @param httpClient
	 * 		the HTTP client to use for BTP tenant API requests
	 * @return configured IasTokenFlows instance (with tenant resolution if BTP API URI is present)
	 */
	public static IasTokenFlows fromConfiguration(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceConfiguration config,
			@Nonnull SecurityHttpClient httpClient) {
		return fromConfiguration(tokenService, config, httpClient,
				IasTenantHostCacheConfiguration.defaultConfiguration());
	}

	/**
	 * Convenience factory: creates IasTokenFlows with an explicit HTTP client and cache configuration.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service
	 * @param config
	 * 		the IAS service configuration (from service binding)
	 * @param httpClient
	 * 		the HTTP client to use for BTP tenant API requests
	 * @param cacheConfiguration
	 * 		cache configuration for the tenant host resolver
	 * @return configured IasTokenFlows instance (with tenant resolution if BTP API URI is present)
	 */
	public static IasTokenFlows fromConfiguration(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceConfiguration config,
			@Nonnull SecurityHttpClient httpClient,
			@Nonnull IasTenantHostCacheConfiguration cacheConfiguration) {
		assertNotNull(config, "OAuth2ServiceConfiguration must not be null.");
		assertNotNull(httpClient, "SecurityHttpClient must not be null.");
		assertNotNull(cacheConfiguration, "IasTenantHostCacheConfiguration must not be null.");
		IasTenantHostResolver resolver = createResolverFromConfig(config, httpClient, cacheConfiguration);
		return new IasTokenFlows(tokenService, new IasDefaultEndpoints(config), config.getClientIdentity(), resolver);
	}

	/**
	 * Convenience factory: creates IasTokenFlows with an explicit BTP tenant API URI.
	 * <p>
	 * Use this when the BTP tenant API URI is not part of the service binding
	 * or needs to be overridden.
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
		return fromConfiguration(tokenService, config, btpTenantApiBaseUri, httpClient,
				IasTenantHostCacheConfiguration.defaultConfiguration());
	}

	/**
	 * Convenience factory: creates IasTokenFlows with an explicit BTP tenant API URI and cache configuration.
	 *
	 * @param tokenService
	 * 		the OAuth2 token service
	 * @param config
	 * 		the IAS service configuration (from service binding)
	 * @param btpTenantApiBaseUri
	 * 		the BTP tenant API base URI for subdomain resolution
	 * @param httpClient
	 * 		the HTTP client for tenant API requests
	 * @param cacheConfiguration
	 * 		cache configuration for the tenant host resolver
	 * @return configured IasTokenFlows instance with tenant resolution
	 */
	public static IasTokenFlows fromConfiguration(@Nonnull OAuth2TokenService tokenService,
			@Nonnull OAuth2ServiceConfiguration config,
			@Nonnull URI btpTenantApiBaseUri,
			@Nonnull SecurityHttpClient httpClient,
			@Nonnull IasTenantHostCacheConfiguration cacheConfiguration) {
		assertNotNull(config, "OAuth2ServiceConfiguration must not be null.");
		assertNotNull(btpTenantApiBaseUri, "BTP tenant API URI must not be null.");
		assertNotNull(httpClient, "SecurityHttpClient must not be null.");
		assertNotNull(cacheConfiguration, "IasTenantHostCacheConfiguration must not be null.");
		IasTenantHostResolver resolver = new IasTenantHostResolver(btpTenantApiBaseUri, httpClient, cacheConfiguration);
		return new IasTokenFlows(tokenService, new IasDefaultEndpoints(config), config.getClientIdentity(), resolver);
	}

	@Nullable
	private static IasTenantHostResolver createResolverFromConfig(OAuth2ServiceConfiguration config,
			@Nullable SecurityHttpClient httpClient,
			IasTenantHostCacheConfiguration cacheConfiguration) {
		String btpTenantApiUrl = config.getProperty(BTP_TENANT_API_PROPERTY);
		if (btpTenantApiUrl == null || btpTenantApiUrl.isBlank()) {
			LOGGER.debug("No '{}' property found in IAS service configuration. "
					+ "Dynamic tenant host resolution will not be available.", BTP_TENANT_API_PROPERTY);
			return null;
		}
		URI btpTenantApiUri = URI.create(btpTenantApiUrl);
		if (httpClient == null) {
			httpClient = SecurityHttpClientProvider.createClient(config.getClientIdentity());
		}
		return new IasTenantHostResolver(btpTenantApiUri, httpClient, cacheConfiguration);
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
