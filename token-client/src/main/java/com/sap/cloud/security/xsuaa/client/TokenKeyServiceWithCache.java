package com.sap.cloud.security.xsuaa.client;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKey;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeyImpl;

public class TokenKeyServiceWithCache {
	private Logger logger = LoggerFactory.getLogger(TokenKeyServiceWithCache.class);

	private final OAuth2TokenKeyService tokenKeyService;
	private final OAuth2ServiceEndpointsProvider endpointsProvider;
	private Cache<String, PublicKey> cache;
	private long cacheValidityInSeconds = 900;
	private long cacheSize = 100;

	/**
	 * Create a new instance of this bean with the given RestTemplate. Applications
	 * should {@code @Autowire} instances of this bean.
	 *
	 * @param tokenKeyService
	 *            the OAuth2TokenKeyService that will be used to request token keys.
	 *
	 *            <pre>
	 * {@code
	 * }
	 *            </pre>
	 */
	public TokenKeyServiceWithCache(OAuth2TokenKeyService tokenKeyService,
			OAuth2ServiceEndpointsProvider endpointsProvider) {
		assertNotNull(tokenKeyService, "tokenKeyService must not be null.");
		assertNotNull(endpointsProvider, "OAuth2ServiceEndpointsProvider must not be null");

		this.tokenKeyService = tokenKeyService;
		this.endpointsProvider = endpointsProvider;
	}

	private Cache<String, PublicKey> getCache() {
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
	public TokenKeyServiceWithCache withCacheTime(int timeInSeconds) {
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
	public TokenKeyServiceWithCache withCacheSize(int size) {
		this.cacheSize = size;
		return this;
	}

	@Nullable
	public PublicKey getPublicKey(JsonWebKey.Type keyType, @Nullable String keyId) {
		String cacheKey = getUniqueCacheKey(keyType, keyId);

		PublicKey publicKey = getCache().getIfPresent(cacheKey);
		if (publicKey == null) {
			retrieveTokenKeysAndFillCache();
		}
		return getCache().getIfPresent(cacheKey);
	}

	private void retrieveTokenKeysAndFillCache() {
		URI jwksUri = endpointsProvider.getJwksUri();
		try {
			Set<JsonWebKey> jwks = tokenKeyService.retrieveTokenKeys(jwksUri).getAll();
			for (JsonWebKey jwk : jwks) {
				getCache().put(getUniqueCacheKey(jwk.getType(), jwk.getId()), jwk.getPublicKey());
			}
		} catch (OAuth2ServiceException e) {
			logger.warn("Error retrieving JSON Web Keys from Identity Service ({}).", jwksUri, e);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			logger.warn("Error creating PublicKey from JSON Web Key received from Identity Service ({}).", jwksUri, e);
		}
	}

	public void clearCache() {
		if (cache != null) {
			cache.invalidateAll();
		}
	}

	public static String getUniqueCacheKey(JsonWebKey.Type type, String keyId) {
		return String.valueOf(JsonWebKeyImpl.calculateUniqueId(type, keyId)); // TODO
	}

}
