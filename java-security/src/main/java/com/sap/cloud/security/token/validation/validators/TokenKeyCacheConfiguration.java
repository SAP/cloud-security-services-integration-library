package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nonnull;
import java.time.Duration;

/**
 *
 */
class TokenKeyCacheConfiguration implements CacheConfiguration {

	private static final TokenKeyCacheConfiguration DEFAULT = TokenKeyCacheConfiguration
			.getInstance(Duration.ofMinutes(10), 1000);

	private Duration cacheDuration;
	private int cacheSize;

	/**
	 * Creates a new {@link TokenKeyCacheConfiguration} instance with the given
	 * properties. See {@link CacheConfiguration#getCacheDuration()} and
	 * {@link CacheConfiguration#getCacheSize()} for an explanation of the
	 * respective properties.
	 *
	 * @param cacheDuration
	 *            the cache duration property.
	 * @param cacheSize
	 *            the cache size property.
	 * @return a new {@link TokenKeyCacheConfiguration} instance.
	 */
	static TokenKeyCacheConfiguration getInstance(Duration cacheDuration, int cacheSize) {
		Assertions.assertNotNull(cacheDuration, "The cache duration write must not be null!");
		return new TokenKeyCacheConfiguration(cacheDuration, cacheSize);
	}

	/**
	 * The default configuration for the token key cache. The default cache size is
	 * 1000. The default cache duration is 10 minutes.
	 * 
	 * @return the default configuration
	 */
	static TokenKeyCacheConfiguration defaultConfiguration() {
		return DEFAULT;
	}

	private TokenKeyCacheConfiguration(Duration cacheDuration, int cacheSize) {
		this.cacheDuration = cacheDuration;
		this.cacheSize = cacheSize;
	}

	@Override
	@Nonnull
	public Duration getCacheDuration() {
		return cacheDuration;
	}

	@Override
	public int getCacheSize() {
		return cacheSize;
	}
}
