/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.tokenflows.Cacheable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;

import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * Decorates {@link OAuth2TokenKeyService} with a cache, which gets looked up
 * before the identity service is requested via http.
 */
class OAuth2TokenKeyServiceWithCache implements Cacheable {
	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2TokenKeyServiceWithCache.class);

	private OAuth2TokenKeyService tokenKeyService;
	private Cache<String, JsonWebKeySet> cache;
	private CacheConfiguration cacheConfiguration = TokenKeyCacheConfiguration.defaultConfiguration();
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
	 *            ticker the cache uses to determine time
	 *
	 * @return the new instance.
	 */
	static OAuth2TokenKeyServiceWithCache getInstance(Ticker cacheTicker) {
		OAuth2TokenKeyServiceWithCache instance = new OAuth2TokenKeyServiceWithCache();
		instance.cacheTicker = cacheTicker;
		return instance;
	}

	/**
	 * Configures the token key cache. Use
	 * {@link TokenKeyCacheConfiguration#getInstance(Duration, int, boolean)} to
	 * pass a custom configuration.
	 * <p>
	 * Note that the cache size must be 1000 or more and the cache duration must be
	 * at least 600 seconds!
	 *
	 * @param cacheConfiguration
	 *            the cache configuration
	 * @return this tokenKeyServiceWithCache
	 */
	public OAuth2TokenKeyServiceWithCache withCacheConfiguration(CacheConfiguration cacheConfiguration) {
		this.cacheConfiguration = getCheckedConfiguration(cacheConfiguration);
		LOGGER.debug(
				"Configured token key cache with cacheDuration={} seconds, cacheSize={} and statisticsRecording={}",
				getCacheConfiguration().getCacheDuration().getSeconds(), getCacheConfiguration().getCacheSize(),
				getCacheConfiguration().isCacheStatisticsEnabled());
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
	 * @param appTid
	 *            the tenant identifier of the tenant
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
	public PublicKey getPublicKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri, String appTid)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		assertNotNull(keyAlgorithm, "keyAlgorithm must not be null.");
		assertHasText(keyId, "keyId must not be null.");
		assertNotNull(keyUri, "keyUrl must not be null.");

		return getPublicKey(keyAlgorithm, keyId, keyUri, appTid, null);
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
	 * @param appTid
	 *            the tenant identifier of the tenant
	 *
	 * @param clientId
	 * 				client id from the service configuration
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
	public PublicKey getPublicKey(JwtSignatureAlgorithm keyAlgorithm, String keyId, URI keyUri, String appTid, String clientId)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException {
		assertNotNull(keyAlgorithm, "keyAlgorithm must not be null.");
		assertHasText(keyId, "keyId must not be null.");
		assertNotNull(keyUri, "keyUrl must not be null.");

		JsonWebKeySet keySet = getCache().getIfPresent(keyUri.toString());
		if (keySet == null || !keySet.containsAppTid(appTid)) {
			keySet = retrieveTokenKeysAndUpdateCache(keyUri, appTid, keySet, clientId); // creates and updates cache entries
		}
		if (keySet == null || keySet.getAll().isEmpty()) {
			LOGGER.error("Retrieved no token keys from {}", keyUri);
			return null;
		}
		if (!keySet.isAppTidAccepted(appTid)) {
			throw new OAuth2ServiceException("Keys not accepted for app_tid " + appTid);
		}
		for (JsonWebKey jwk : keySet.getAll()) {
			if (keyId.equals(jwk.getId()) && jwk.getKeyAlgorithm().equals(keyAlgorithm)) {
				return jwk.getPublicKey();
			}
		}
		LOGGER.warn("No matching key found. Keys cached: {}", keySet);
		return null;
	}

	private TokenKeyCacheConfiguration getCheckedConfiguration(CacheConfiguration cacheConfiguration) {
		Assertions.assertNotNull(cacheConfiguration, "CacheConfiguration must not be null!");
		int size = cacheConfiguration.getCacheSize();
		Duration duration = cacheConfiguration.getCacheDuration();
		if (size < 1000) {
			int currentSize = getCacheConfiguration().getCacheSize();
			LOGGER.error("Tried to set cache size to {} but the cache size must be 1000 or more."
					+ " Cache size will remain at: {}", size, currentSize);
			size = currentSize;
		}
		if (duration.getSeconds() < 600) {
			Duration currentDuration = getCacheConfiguration().getCacheDuration();
			LOGGER.error(
					"Tried to set cache duration to {} seconds but the cache duration must be at least 600 seconds."
							+ " Cache duration will remain at: {} seconds",
					duration.getSeconds(), currentDuration.getSeconds());
			duration = currentDuration;
		}
		if (duration.getSeconds() > 900) {
			Duration currentDuration = getCacheConfiguration().getCacheDuration();
			LOGGER.error(
					"Tried to set cache duration to {} seconds but the cache duration must be maximum 900 seconds."
							+ " Cache duration will remain at: {} seconds",
					duration.getSeconds(), currentDuration.getSeconds());
			duration = currentDuration;
		}
		return TokenKeyCacheConfiguration.getInstance(duration, size, cacheConfiguration.isCacheStatisticsEnabled());
	}

	private JsonWebKeySet retrieveTokenKeysAndUpdateCache(URI jwksUri, String appTid,
			@Nullable JsonWebKeySet keySetCached, String clientId)
			throws OAuth2ServiceException {
		String jwksJson;
		try {
			jwksJson = getTokenKeyService().retrieveTokenKeys(jwksUri, appTid, clientId);
		} catch (OAuth2ServiceException e) {
			if (keySetCached != null) {
				keySetCached.withAppTid(appTid, false);
			}
			throw e;
		}
		if (keySetCached != null) {
			return keySetCached.withAppTid(appTid, true);
		}
		JsonWebKeySet keySet = JsonWebKeySetFactory.createFromJson(jwksJson).withAppTid(appTid, true);
		getCache().put(jwksUri.toString(), keySet);
		return keySet;
	}

	private Cache<String, JsonWebKeySet> getCache() {
		if (cache == null) {
			Caffeine<Object, Object> cacheBuilder = Caffeine.newBuilder()
					.ticker(cacheTicker)
					.expireAfterWrite(getCacheConfiguration().getCacheDuration())
					.maximumSize(getCacheConfiguration().getCacheSize());
			if (getCacheConfiguration().isCacheStatisticsEnabled()) {
				cacheBuilder.recordStats();
			}
			cache = cacheBuilder.build();
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

	@Override
	public Object getCacheStatistics() {
		return getCacheConfiguration().isCacheStatisticsEnabled() ? getCache().stats() : null;
	}

}
