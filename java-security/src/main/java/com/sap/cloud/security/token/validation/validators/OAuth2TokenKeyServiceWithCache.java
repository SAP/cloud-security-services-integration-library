package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;

/**
 * Decorates {@link OAuth2TokenKeyService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
public class OAuth2TokenKeyServiceWithCache {
	private OAuth2TokenKeyService tokenKeyService; // access via getter
	private Cache<String, JsonWebKeySet> cache; // access via getter
	private long cacheValidityInSeconds = 600; // old keys should expire after 10 minutes
	private long cacheSize = 1000;
	private Ticker cacheTicker;

	private OAuth2TokenKeyServiceWithCache() {
		// use getInstance factory method
	}

	/**
	 * Creates a new instance.
	 *
	 * @return the new instance.
	 */
	public static OAuth2TokenKeyServiceWithCache getInstance() {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = Ticker.systemTicker();
		return instance;
	}

	/**
	 * Creates a new instance and sets the cache ticker. This is used for testing.
	 *
	 * @param cacheTicker
	 * 			ticker the cache uses to determine time
	 *
	 * @return the new instance.
	 */
	static OAuth2TokenKeyServiceWithCache getInstance(Ticker cacheTicker) {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = cacheTicker;
		return instance;
	}

	/**
	 * Caches the Json web keys. Overwrite the cache time (default: 900 seconds).
	 *
	 * @param timeInSeconds
	 *            time to cache the signing keys
	 * @return this
	 */
	public OAuth2TokenKeyServiceWithCache withCacheTime(int timeInSeconds) {
		if (timeInSeconds <= 600) {
			throw new IllegalArgumentException("The cache validity must be minimum 600 seconds");
		}
		this.cacheValidityInSeconds = timeInSeconds;
		return this;
	}

	/**
	 * Caches the Json web keys. Overwrite the size of the cache (default: 100).
	 *
	 * @param size
	 *            number of cached json web keys.
	 * @return this
	 */
	public OAuth2TokenKeyServiceWithCache withCacheSize(int size) {
		if (size <= 1000) {
			throw new IllegalArgumentException("The cache size must be 1000 or more");
		}
		this.cacheSize = size;
		return this;
	}

	/**
	 * Overwrites the service to be used to request the Json web keys.
	 *
	 * @param tokenKeyService
	 *            the service to request the json web key set.
	 * @return this
	 */
	public OAuth2TokenKeyServiceWithCache withTokenKeyService(OAuth2TokenKeyService tokenKeyService) {
		this.tokenKeyService = tokenKeyService;
		return this;
	}

	/**
	 * Returns the cached key by id and type or requests the keys from the jwks URI
	 * of the identity service.
	 *
	 * @param keyAlgorithm
	 *            the Key Algorithm of the Access Token.
	 * @param keyId
	 *            the Key Id of the Access Token.
	 * @param keyUri
	 *            the Token Key Uri (jwks) of the Access Token (can be tenant
	 *            specific).
	 * @return a PublicKey
	 * @throws OAuth2ServiceException
	 *             in case the call to the jwks endpoint of the identity service
	 *             failed.
	 * @throws InvalidKeySpecException
	 *             in case the PublicKey generation for the json web key failed.
	 * @throws NoSuchAlgorithmException
	 *             in case the algorithm of the json web key is not supported.
	 *
	 */
	@Nullable
	public PublicKey getPublicKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		assertNotNull(keyAlgorithm, "keyAlgorithm must not be null.");
		assertHasText(keyId, "keyId must not be null.");
		assertNotNull(keyUri, "keyUrl must not be null.");

		String cacheKey = getUniqueCacheKey(keyUri);

		JsonWebKeySet jsonWebKeySet = getCache().getIfPresent(cacheKey);
		if (jsonWebKeySet == null) {
			retrieveTokenKeysAndFillCache(keyUri);
		}
		JsonWebKey jsonWebKey = getMatchingJsonWebKeyFromCache(cacheKey, keyAlgorithm, keyId);
		return jsonWebKey == null ? null : jsonWebKey.getPublicKey();
	}

	@Nullable
	private JsonWebKey getMatchingJsonWebKeyFromCache(String cacheKey, JwtSignatureAlgorithm algorithm, String keyId) {
		JsonWebKeySet jsonWebKeySet = getCache().getIfPresent(cacheKey);
		return jsonWebKeySet == null ? null : jsonWebKeySet.getKeyByAlgorithmAndId(algorithm, keyId);
	}

	private void retrieveTokenKeysAndFillCache(URI jwksUri) throws OAuth2ServiceException {
		JsonWebKeySet keySet = JsonWebKeySetFactory.createFromJson(getTokenKeyService().retrieveTokenKeys(jwksUri));
		if (keySet == null) {
			return;
		}
		getCache().put(getUniqueCacheKey(jwksUri), keySet);
	}

	private Cache<String, JsonWebKeySet> getCache() {
		if (cache == null) {
			cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS)
					.ticker(cacheTicker)
					.maximumSize(cacheSize)
					.build();
		}
		return cache;
	}

	private OAuth2TokenKeyService getTokenKeyService() {
		if (tokenKeyService == null) {
			this.tokenKeyService = new DefaultOAuth2TokenKeyService();
		}
		return tokenKeyService;
	}

	public void clearCache() {
		if (cache != null) {
			cache.invalidateAll();
		}
	}

	public static String getUniqueCacheKey(URI jwksUri) {
		return jwksUri.toString();
	}

}
