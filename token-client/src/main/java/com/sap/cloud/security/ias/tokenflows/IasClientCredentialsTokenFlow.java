/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import com.sap.cloud.security.ias.client.IasDefaultEndpoints;
import com.sap.cloud.security.ias.client.IasTenantHostCacheConfiguration;
import com.sap.cloud.security.ias.client.IasTenantHostResolver;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * A client credentials flow builder for IAS (Identity Authentication Service).
 * <p>
 * Applications use this to request technical user tokens from IAS.
 * Unlike the XSUAA counterpart, this flow uses IAS-specific parameters:
 * <ul>
 *   <li>{@code app_tid} - the tenant ID for multi-tenant scenarios</li>
 *   <li>{@code resource} - the target application URN for app-to-app communication</li>
 *   <li>{@code token_format} - optional format parameter (e.g. "jwt")</li>
 * </ul>
 */
public class IasClientCredentialsTokenFlow {

	private static final Logger LOGGER = LoggerFactory.getLogger(IasClientCredentialsTokenFlow.class);

	static final String APP_TID = "app_tid";
	static final String RESOURCE = "resource";
	static final String TOKEN_FORMAT = "token_format";
	static final String RESOURCE_URN_PREFIX = "urn:sap:identity:application:provider:name:";

	private final OAuth2TokenService tokenService;
	private final IasDefaultEndpoints endpointsProvider;
	private final ClientIdentity clientIdentity;
	private final IasTenantHostResolver tenantHostResolver;

	private String appTid;
	private String resource;
	private String tokenFormat;
	private boolean disableCache = false;

	IasClientCredentialsTokenFlow(@Nonnull OAuth2TokenService tokenService,
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
	 * Sets the tenant ID for multi-tenant token requests.
	 * <p>
	 * This is the subscriber's tenant ID (subaccount ID). If set, the token will be scoped
	 * to this tenant. If a {@link IasTenantHostResolver} is configured, the subdomain
	 * will be resolved dynamically.
	 *
	 * @param appTid
	 * 		the tenant ID
	 * @return this builder.
	 */
	public IasClientCredentialsTokenFlow appTid(@Nonnull String appTid) {
		this.appTid = appTid;
		return this;
	}

	/**
	 * Sets the target application name for app-to-app communication.
	 * <p>
	 * This will be converted to the IAS resource URN format:
	 * {@code urn:sap:identity:application:provider:name:{applicationName}}
	 *
	 * @param applicationName
	 * 		the target application's registered name in IAS
	 * @return this builder.
	 */
	public IasClientCredentialsTokenFlow resource(@Nonnull String applicationName) {
		assertNotNull(applicationName, "Application name must not be null.");
		this.resource = RESOURCE_URN_PREFIX + applicationName;
		return this;
	}

	/**
	 * Sets the resource URN directly for app-to-app communication.
	 * <p>
	 * Use this if you have a pre-built URN, e.g. with a client ID reference:
	 * {@code urn:sap:identity:application:provider:clientid:{clientId}}
	 *
	 * @param resourceUrn
	 * 		the full resource URN
	 * @return this builder.
	 */
	public IasClientCredentialsTokenFlow resourceUrn(@Nonnull String resourceUrn) {
		assertNotNull(resourceUrn, "Resource URN must not be null.");
		this.resource = resourceUrn;
		return this;
	}

	/**
	 * Sets the desired token format.
	 *
	 * @param tokenFormat
	 * 		the token format, e.g. "jwt"
	 * @return this builder.
	 */
	public IasClientCredentialsTokenFlow tokenFormat(@Nonnull String tokenFormat) {
		this.tokenFormat = tokenFormat;
		return this;
	}

	/**
	 * Disables the token cache for this request.
	 *
	 * @param disableCache
	 * 		{@code true} to disable caching
	 * @return this builder.
	 */
	public IasClientCredentialsTokenFlow disableCache(boolean disableCache) {
		this.disableCache = disableCache;
		return this;
	}

	/**
	 * Executes the client credentials flow against the IAS token endpoint.
	 *
	 * @return the OAuth2 token response
	 * @throws TokenFlowException
	 * 		if the token request fails
	 */
	@Nonnull
	public OAuth2TokenResponse execute() throws TokenFlowException {
		Map<String, String> requestParameters = new HashMap<>();

		if (appTid != null) {
			requestParameters.put(APP_TID, appTid);
		}
		if (resource != null) {
			requestParameters.put(RESOURCE, resource);
		}
		if (tokenFormat != null) {
			requestParameters.put(TOKEN_FORMAT, tokenFormat);
		}

		URI tokenEndpoint = resolveTokenEndpoint();

		try {
			return tokenService.retrieveAccessTokenViaClientCredentialsGrant(
					tokenEndpoint,
					clientIdentity,
					null,
					null,
					requestParameters,
					disableCache);
		} catch (OAuth2ServiceException e) {
			throw new TokenFlowException(
					"Error requesting IAS technical user token with grant_type 'client_credentials': %s".formatted(
							e.getMessage()),
					e);
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
