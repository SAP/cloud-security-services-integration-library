package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nonnull;
import java.time.Duration;
import java.util.Objects;

/**
 * Data class to capture configuration options of token caches.
 */
public class TokenCacheConfiguration implements CacheConfiguration {

	private static final TokenCacheConfiguration DEFAULT = new TokenCacheConfiguration(Duration.ofMinutes(10), 1000,
			Duration.ofSeconds(30));

	private static final TokenCacheConfiguration CACHE_DISABLED = new DisabledCache();

	private final Duration cacheDuration;
	private final int cacheSize;
	private final Duration tokenExpirationDelta;

	/**
	 * Creates a new {@link TokenCacheConfiguration} instance with the given properties.
	 * See {@link TokenCacheConfiguration#getCacheDuration()},
	 * {@link TokenCacheConfiguration#getCacheSize()} and
	 * {@link TokenCacheConfiguration#getTokenExpirationDelta()} for a explanation of the
	 * respective properties.
	 *
	 * @param cacheDuration        the cache duration property.
	 * @param cacheSize            the cache size property.
	 * @param tokenExpirationDelta the token expiration delta.
	 * @return a new {@link TokenCacheConfiguration} instance.
	 */
	public static TokenCacheConfiguration getInstance(@Nonnull Duration cacheDuration, int cacheSize,
			@Nonnull Duration tokenExpirationDelta) {
		Assertions.assertNotNull(cacheDuration, "The cache duration write must not be null!");
		return new TokenCacheConfiguration(cacheDuration, cacheSize, tokenExpirationDelta);
	}

	/**
	 * The default cache configuration.
	 */
	public static TokenCacheConfiguration cacheDisabled() {
		return CACHE_DISABLED;
	}

	/**
	 * A special cache configuration used to disable caching.
	 */
	public static TokenCacheConfiguration defaultConfiguration() {
		return DEFAULT;
	}

	private TokenCacheConfiguration(Duration cacheDuration, int cacheSize, Duration tokenExpirationDelta) {
		this.cacheDuration = cacheDuration;
		this.cacheSize = cacheSize;
		this.tokenExpirationDelta = tokenExpirationDelta;
	}

	@Nonnull
	@Override
	public Duration getCacheDuration() {
		return cacheDuration;
	}

	@Override
	public int getCacheSize() {
		return cacheSize;
	}

	/**
	 * If a cached token expires because its expiration time (exp) has been reached,
	 * it should not be retrieved from the cache. A new token should be requested in
	 * this case. For this to work cached tokens are being checked if their
	 * expiration time (exp) has already been reached or if it is soon going to be
	 * reached. The expiration delta controls what <em>soon</em> means. For example
	 * if the expiration delta is set to 10 seconds and a cached token will expire
	 * in 5 seconds, it will not be retrieved from cache anymore because the
	 * duration until the token is expired is smaller than delta.
	 *
	 * @return the token expiration delta.
	 */
	public Duration getTokenExpirationDelta() {
		return tokenExpirationDelta;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		TokenCacheConfiguration that = (TokenCacheConfiguration) o;
		return cacheSize == that.cacheSize &&
				Objects.equals(cacheDuration, that.cacheDuration);
	}

	@Override
	public int hashCode() {
		return Objects.hash(cacheDuration, cacheSize);
	}

	private static class DisabledCache extends TokenCacheConfiguration {

		private DisabledCache() {
			super(Duration.ZERO, 0, Duration.ZERO);
		}

		@Override
		public boolean isCacheDisabled() {
			return true;
		}
	}
}
