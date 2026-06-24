/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.client.SecurityHttpClient;
import com.sap.cloud.security.client.SecurityHttpRequest;
import com.sap.cloud.security.client.SecurityHttpResponse;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.io.IOException;
import java.net.URI;
import java.util.concurrent.atomic.AtomicReference;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves subscriber IAS tenant hosts dynamically by querying the BTP tenant API.
 * <p>
 * When a multi-tenant IAS application needs to fetch tokens for a subscriber tenant,
 * the IAS token endpoint URL changes based on the subscriber's subdomain.
 * This resolver queries {@code /sap/rest/tenantLoginInfo?id={tenantId}} to discover
 * the subscriber's token endpoint and extracts the subdomain from it.
 * <p>
 * Resolved subdomains are cached via Caffeine. The cache behavior is controlled by an
 * {@link IasTenantHostCacheConfiguration}; pass a config with {@code enabled=false} to disable
 * caching entirely.
 */
public class IasTenantHostResolver {

	private static final Logger LOGGER = LoggerFactory.getLogger(IasTenantHostResolver.class);
	private static final String TENANT_LOGIN_INFO_PATH = "/sap/rest/tenantLoginInfo";

	private final URI btpTenantApiBaseUri;
	private final SecurityHttpClient httpClient;
	private final IasTenantHostCacheConfiguration cacheConfiguration;
	@Nullable
	private final Cache<String, String> subdomainCache;

	/**
	 * Creates a new resolver with the default cache configuration
	 * ({@link IasTenantHostCacheConfiguration#defaultConfiguration()}).
	 *
	 * @param btpTenantApiBaseUri
	 * 		base URI of the BTP tenant API, e.g. {@code https://api.authentication.eu10.hana.ondemand.com}
	 * @param httpClient
	 * 		HTTP client to use for requests
	 */
	public IasTenantHostResolver(@Nonnull URI btpTenantApiBaseUri, @Nonnull SecurityHttpClient httpClient) {
		this(btpTenantApiBaseUri, httpClient, IasTenantHostCacheConfiguration.defaultConfiguration());
	}

	/**
	 * Creates a new resolver with an explicit cache configuration.
	 *
	 * @param btpTenantApiBaseUri
	 * 		base URI of the BTP tenant API
	 * @param httpClient
	 * 		HTTP client to use for requests
	 * @param cacheConfiguration
	 * 		cache configuration; pass a disabled config to skip caching
	 */
	public IasTenantHostResolver(@Nonnull URI btpTenantApiBaseUri, @Nonnull SecurityHttpClient httpClient,
			@Nonnull IasTenantHostCacheConfiguration cacheConfiguration) {
		this.btpTenantApiBaseUri = btpTenantApiBaseUri;
		this.httpClient = httpClient;
		this.cacheConfiguration = cacheConfiguration;
		this.subdomainCache = cacheConfiguration.enabled()
				? Caffeine.newBuilder()
						.expireAfterWrite(cacheConfiguration.ttl())
						.maximumSize(cacheConfiguration.maxSize())
						.build()
				: null;
	}

	/**
	 * Resolves the IAS subdomain for a given tenant ID.
	 * <p>
	 * Queries the BTP tenant API; if caching is enabled, subsequent calls with the same tenant ID
	 * return the cached value until the TTL expires.
	 *
	 * @param tenantId
	 * 		the subscriber tenant ID (app_tid / subaccount ID)
	 * @return the resolved IAS subdomain, or {@code null} if resolution returned no subdomain
	 * @throws OAuth2ServiceException
	 * 		if the HTTP request fails with an error response
	 */
	@Nullable
	public String resolve(@Nonnull String tenantId) throws OAuth2ServiceException {
		if (subdomainCache == null) {
			return doResolve(tenantId);
		}
		AtomicReference<OAuth2ServiceException> thrown = new AtomicReference<>();
		String resolved = subdomainCache.get(tenantId, key -> {
			try {
				return doResolve(key);
			} catch (OAuth2ServiceException e) {
				thrown.set(e);
				return null;
			}
		});
		if (thrown.get() != null) {
			throw thrown.get();
		}
		return resolved;
	}

	private String doResolve(String tenantId) throws OAuth2ServiceException {
		URI requestUri = URI.create(btpTenantApiBaseUri + TENANT_LOGIN_INFO_PATH + "?id=" + tenantId);
		LOGGER.debug("Resolving IAS subdomain for tenant '{}' via {}", tenantId, requestUri);

		SecurityHttpRequest request = SecurityHttpRequest.newBuilder()
				.method("GET")
				.uri(requestUri)
				.header("Accept", "application/json")
				.build();

		try {
			SecurityHttpResponse response = httpClient.execute(request);
			if (response.getStatusCode() != 200) {
				LOGGER.warn("BTP tenant API returned status {} for tenant '{}': {}",
						response.getStatusCode(), tenantId, response.getBody());
				throw new OAuth2ServiceException(
						"Failed to resolve IAS subdomain for tenant '%s': HTTP %d".formatted(
								tenantId, response.getStatusCode()));
			}
			String subdomain = extractSubdomainFromResponse(response.getBody());
			LOGGER.debug("Resolved IAS subdomain for tenant '{}': '{}'", tenantId, subdomain);
			return subdomain;
		} catch (IOException e) {
			throw new OAuth2ServiceException(
					"Failed to resolve IAS subdomain for tenant '%s': %s".formatted(tenantId, e.getMessage()));
		}
	}

	/**
	 * Extracts the IAS subdomain from the tenantLoginInfo API response.
	 * The response contains a {@code token_endpoint} field like
	 * {@code https://subscriber.accounts.ondemand.com/oauth2/token}.
	 * We extract the first host label as the subdomain.
	 */
	static String extractSubdomainFromResponse(String responseBody) {
		JSONObject json = new JSONObject(responseBody);
		String tokenEndpoint = json.getString("token_endpoint");
		URI tokenUri = URI.create(tokenEndpoint);
		String host = tokenUri.getHost();
		int dotIndex = host.indexOf('.');
		if (dotIndex < 0) {
			return host;
		}
		return host.substring(0, dotIndex);
	}

	/**
	 * @return the cache configuration this resolver was constructed with
	 */
	@Nonnull
	public IasTenantHostCacheConfiguration getCacheConfiguration() {
		return cacheConfiguration;
	}

	/**
	 * Clears the subdomain cache. No-op if caching is disabled.
	 */
	public void clearCache() {
		if (subdomainCache != null) {
			subdomainCache.invalidateAll();
		}
	}
}
