package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Set;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.config.TokenKeyCacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;

/**
 * Decorates {@link OAuth2TokenKeyService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
public class OAuth2TokenKeyServiceWithCache implements Cacheable {
	private OAuth2TokenKeyService tokenKeyService; // access via getter
	private Cache<String, PublicKey> cache; // access via getter
	private CacheConfiguration cacheConfiguration = TokenKeyCacheConfiguration.defaultConfiguration();

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
		withCacheConfiguration(TokenKeyCacheConfiguration
				.getInstance(Duration.ofSeconds(timeInSeconds), this.cacheConfiguration.getCacheSize()));
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
		withCacheConfiguration(TokenKeyCacheConfiguration.getInstance(cacheConfiguration.getCacheDuration(), size));
		return this;
	}

	/**
	 * Use to configure the token key cache.
	 *
	 * @param cacheConfiguration the cache configuration
	 * @return this tokenKeyServiceWithCache
	 */
	public OAuth2TokenKeyServiceWithCache withCacheConfiguration(CacheConfiguration cacheConfiguration) {
		checkCacheConfiguration(cacheConfiguration);
		this.cacheConfiguration = cacheConfiguration;
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

		String cacheKey = getUniqueCacheKey(keyAlgorithm, keyId, keyUri);

		PublicKey publicKey = getCache().getIfPresent(cacheKey);
		if (publicKey == null) {
			retrieveTokenKeysAndFillCache(keyUri);
		}
		return getCache().getIfPresent(cacheKey);
	}

	private void checkCacheConfiguration(CacheConfiguration cacheConfiguration) {
		Assertions.assertNotNull(cacheConfiguration, "CacheConfiguration must not be null!");
		int size = cacheConfiguration.getCacheSize();
		long timeInSeconds = cacheConfiguration.getCacheDuration().getSeconds();
		if (size < 1000) {
			throw new IllegalArgumentException("The cache size must be 1000 or more");
		}
		if (timeInSeconds < 600) {
			throw new IllegalArgumentException("The cache validity must be minimum 600 seconds");
		}
	}

	private void retrieveTokenKeysAndFillCache(URI jwksUri)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		JsonWebKeySet keySet = JsonWebKeySetFactory.createFromJson(getTokenKeyService().retrieveTokenKeys(jwksUri));
		if (keySet == null) {
			return;
		}
		Set<JsonWebKey> jwks = keySet.getAll();
		for (JsonWebKey jwk : jwks) {
			getCache().put(getUniqueCacheKey(jwk.getKeyAlgorithm(), jwk.getId(), jwksUri), jwk.getPublicKey());
		}
	}

	private Cache<String, PublicKey> getCache() {
		if (cache == null) {
			cache = Caffeine.newBuilder()
					.expireAfterWrite(cacheConfiguration.getCacheDuration())
					.maximumSize(cacheConfiguration.getCacheSize())
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

	@Nonnull
	@Override
	public CacheConfiguration getCacheConfiguration() {
		return cacheConfiguration;
	}

	@Override
	public void clearCache() {
		if (cache != null) {
			cache.invalidateAll();
		}
	}

	public static String getUniqueCacheKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI jwksUri) {
		return jwksUri + String.valueOf(JsonWebKeyImpl.calculateUniqueId(keyAlgorithm, keyId));
	}

}
