/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nullable;

import java.net.URI;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.client.DefaultOidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationService;

/**
 * Decorates {@link OidcConfigurationService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
public class OidcConfigurationServiceWithCache {
	private OidcConfigurationService oidcConfigurationService; // access via getter
	private Cache<String, OAuth2ServiceEndpointsProvider> cache;
	private long cacheValidityInSeconds = 600; // old keys should expire after 10 minutes
	private static final long MAX_CACHE_VALIDITY_IN_SECONDS = 900; // time-to-live shouldn't exceed 15 minutes
	private long cacheSize = 1000;

	private OidcConfigurationServiceWithCache() {
		// use getInstance factory method
	}

	/**
	 * Creates a new instance.
	 *
	 * @return the new instance.
	 */
	public static OidcConfigurationServiceWithCache getInstance() {
		return new OidcConfigurationServiceWithCache();
	}

	/**
	 * Overwrites the service to be used to request the oidc configuration.
	 *
	 * @param oidcConfigurationService
	 *            * the OidcConfigurationService that will be used to request the
	 *            oidc configuration.
	 * @return this
	 */
	public OidcConfigurationServiceWithCache withOidcConfigurationService(
			OidcConfigurationService oidcConfigurationService) {
		this.oidcConfigurationService = oidcConfigurationService;
		return this;
	}

	/**
	 * Caches the Json web keys. Overwrite the cache time (default: 900 seconds).
	 *
	 * @param timeInSeconds
	 *            time to cache the signing keys
	 * @return this
	 */
	public OidcConfigurationServiceWithCache withCacheTime(int timeInSeconds) {
		if (timeInSeconds < 600 || timeInSeconds > MAX_CACHE_VALIDITY_IN_SECONDS) {
			throw new IllegalArgumentException("The cache validity must be between 600 and 900 seconds.");
		}
		this.cacheValidityInSeconds = timeInSeconds;
		return this;
	}

	/**
	 *
	 * Caches the Json web keys. Overwrite the size of the cache (default: 100).
	 *
	 * @param size
	 *            number of cached json web keys.
	 * @return this
	 */
	public OidcConfigurationServiceWithCache withCacheSize(int size) {
		if (size <= 1000) {
			throw new IllegalArgumentException("The cache size must be 1000 or more");
		}
		this.cacheSize = size;
		return this;
	}

	/**
	 * Returns the cached key by id and type or requests the keys from the jwks URI
	 * of the identity service.
	 *
	 * @param discoveryEndpointUri
	 *            the discovery endpoint URI (issuer specific).
	 * @return a PublicKey
	 * @throws OAuth2ServiceException
	 *             in case the call to the jwks endpoint of the identity service
	 *             failed.
	 */
	@Nullable
	public OAuth2ServiceEndpointsProvider getOrRetrieveEndpoints(URI discoveryEndpointUri)
			throws OAuth2ServiceException {
		assertNotNull(discoveryEndpointUri, "discoveryEndpointUri must not be null.");
		String cacheKey = discoveryEndpointUri.toString();
		OAuth2ServiceEndpointsProvider endpointsProvider = getCache().getIfPresent(cacheKey);
		if (endpointsProvider == null) {
			endpointsProvider = getOidcConfigurationService().retrieveEndpoints(discoveryEndpointUri);
			if (endpointsProvider == null) {
				return null;
			}
			getCache().put(cacheKey, endpointsProvider);
		}
		return getCache().getIfPresent(cacheKey);
	}

	private Cache<String, OAuth2ServiceEndpointsProvider> getCache() {
		if (cache == null) {
			cache = Caffeine.newBuilder()
					.expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS)
					.maximumSize(cacheSize)
					.build();
		}
		return cache;
	}

	private OidcConfigurationService getOidcConfigurationService() {
		if (oidcConfigurationService == null) {
			this.oidcConfigurationService = new DefaultOidcConfigurationService();
		}
		return oidcConfigurationService;
	}

	public void clearCache() {
		if (cache != null) {
			cache.invalidateAll();
		}
	}

}
