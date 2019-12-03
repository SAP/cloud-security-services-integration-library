package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

public class OidcConfigurationServiceWithCache {
	private final OidcConfigurationService oidcConfigurationService;
	private Cache<String, OAuth2ServiceEndpointsProvider> cache;
	private long cacheValidityInSeconds = 6000;
	private long cacheSize = 100;

	/**
	 * Create a new instance of this bean with the given RestTemplate. Applications
	 * should {@code @Autowire} instances of this bean.
	 *
	 * @param configService
	 *            the OAuth2TokenKeyService that will be used to request token keys.
	 *
	 *            <pre>
	 * {@code
	 * }
	 *            </pre>
	 */
	public OidcConfigurationServiceWithCache(OidcConfigurationService configService) {
		assertNotNull(configService, "configService must not be null.");

		this.oidcConfigurationService = configService;
	}

	private Cache<String, OAuth2ServiceEndpointsProvider> getCache() {
		if (cache == null) {
			cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS)
					.maximumSize(cacheSize)
					.build();
		}
		return cache;
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
	 * @throws InvalidKeySpecException
	 *             in case the PublicKey generation for the json web key failed.
	 * @throws NoSuchAlgorithmException
	 *             in case the algorithm of the json web key is not supported.
	 */
	@Nullable
	public OAuth2ServiceEndpointsProvider getEndpoints(URI discoveryEndpointUri)
			throws OAuth2ServiceException {

		assertNotNull(discoveryEndpointUri, "discoveryEndpointUri must not be null.");
		String cacheKey = discoveryEndpointUri.toString();
		OAuth2ServiceEndpointsProvider endpointsProvider = getCache().getIfPresent(cacheKey);
		if (endpointsProvider == null) {
			endpointsProvider = oidcConfigurationService.retrieveEndpoints(discoveryEndpointUri);
			getCache().put(cacheKey, endpointsProvider);
		}
		return getCache().getIfPresent(cacheKey);
	}

	public void clearCache() {
		if (cache != null) {
			cache.invalidateAll();
		}
	}

}
