package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nullable;

import java.net.URI;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

/**
 * Decorates {@link OidcConfigurationService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
public class OidcConfigurationServiceWithCache {
	private OidcConfigurationService oidcConfigurationService; // access via getter
	private Cache<String, OAuth2ServiceEndpointsProvider> cache;
	private long cacheValidityInSeconds = 6000;
	private long cacheSize = 100;

	private OidcConfigurationServiceWithCache() {
		// use getInstance factory method
	}

	/**
	 * Creates a new instance.
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
			getCache().put(cacheKey, endpointsProvider);
		}
		return getCache().getIfPresent(cacheKey);
	}

	private Cache<String, OAuth2ServiceEndpointsProvider> getCache() {
		if (cache == null) {
			cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS)
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
