package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKey;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeyImpl;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;

/**
 * Decorates {@link OAuth2TokenKeyService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
public class OAuth2TokenKeyServiceWithCache {
	private OAuth2TokenKeyService tokenKeyService; // access via getter
	private Cache<String, PublicKey> cache; // access via getter
	private long cacheValidityInSeconds = 900;
	private long cacheSize = 100;

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

		String cacheKey = getUniqueCacheKey(keyAlgorithm, keyId, keyUri);

		PublicKey publicKey = getCache().getIfPresent(cacheKey);
		if (publicKey == null) {
			retrieveTokenKeysAndFillCache(keyUri);
		}
		return getCache().getIfPresent(cacheKey);
	}

	private void retrieveTokenKeysAndFillCache(URI jwksUri)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		Set<JsonWebKey> jwks = getTokenKeyService().retrieveTokenKeys(jwksUri).getAll();
		for (JsonWebKey jwk : jwks) {
			getCache().put(getUniqueCacheKey(jwk.getKeyAlgorithm(), jwk.getId(), jwksUri), jwk.getPublicKey());
		}
	}

	private Cache<String, PublicKey> getCache() {
		if (cache == null) {
			cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS)
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

	public static String getUniqueCacheKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI jwksUri) {
		return jwksUri + String.valueOf(JsonWebKeyImpl.calculateUniqueId(keyAlgorithm, keyId));
	}

}
