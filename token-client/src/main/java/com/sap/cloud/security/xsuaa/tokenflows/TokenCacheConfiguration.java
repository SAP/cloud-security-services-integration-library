/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
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
			Duration.ofSeconds(30), false);

	private static final TokenCacheConfiguration CACHE_DISABLED = new DisabledCache();

	private final Duration cacheDuration;
	private final int cacheSize;
	private final Duration tokenExpirationDelta;
	private final boolean cacheStatisticsEnabled;

	/**
	 * Creates a new {@link TokenCacheConfiguration} instance with the given properties. See
	 * {@link CacheConfiguration#getCacheDuration()}, {@link CacheConfiguration#getCacheSize()} and
	 * {@link TokenCacheConfiguration#getTokenExpirationDelta()} for an explanation of the respective properties.
	 *
	 * @param cacheDuration
	 * 		the cache duration property.
	 * @param cacheSize
	 * 		the cache size property.
	 * @param tokenExpirationDelta
	 * 		the token expiration delta.
	 * @return a new {@link TokenCacheConfiguration} instance.
	 */
	public static TokenCacheConfiguration getInstance(@Nonnull Duration cacheDuration, int cacheSize,
			@Nonnull Duration tokenExpirationDelta) {
		Assertions.assertNotNull(cacheDuration, "The cache duration write must not be null!");
		return new TokenCacheConfiguration(cacheDuration, cacheSize, tokenExpirationDelta, false);
	}

	/**
	 * Creates a new {@link TokenCacheConfiguration} instance with the given properties. See
	 * {@link CacheConfiguration#getCacheDuration()}, {@link CacheConfiguration#getCacheSize()},
	 * {@link TokenCacheConfiguration#getTokenExpirationDelta()} and
	 * {@link CacheConfiguration#isCacheStatisticsEnabled()} for an explanation of the respective properties.
	 *
	 * @param cacheDuration
	 * 		the cache duration property.
	 * @param cacheSize
	 * 		the cache size property.
	 * @param tokenExpirationDelta
	 * 		the token expiration delta.
	 * @param cacheStatisticsEnabled
	 *        {@code true} if cache statistic recording has been enabled
	 * @return a new {@link TokenCacheConfiguration} instance.
	 */
	public static TokenCacheConfiguration getInstance(Duration cacheDuration, int cacheSize,
			Duration tokenExpirationDelta, boolean cacheStatisticsEnabled) {
		return new TokenCacheConfiguration(cacheDuration, cacheSize, tokenExpirationDelta, cacheStatisticsEnabled);
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

	private TokenCacheConfiguration(Duration cacheDuration, int cacheSize, Duration tokenExpirationDelta,
			boolean cacheStatisticsEnabled) {
		this.cacheDuration = cacheDuration;
		this.cacheSize = cacheSize;
		this.tokenExpirationDelta = tokenExpirationDelta;
		this.cacheStatisticsEnabled = cacheStatisticsEnabled;
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
	 * If a cached token expires because its expiration time (exp) has been reached, it should not be retrieved from the
	 * cache. A new token should be requested in this case. For this to work cached tokens are being checked if their
	 * expiration time (exp) has already been reached or if it is soon going to be reached. The expiration delta
	 * controls what <em>soon</em> means. For example if the expiration delta is set to 10 seconds and a cached token
	 * will expire in 5 seconds, it will not be retrieved from cache anymore because the duration until the token is
	 * expired is smaller than delta.
	 *
	 * @return the token expiration delta.
	 */
	public Duration getTokenExpirationDelta() {
		return tokenExpirationDelta;
	}

	@Override
	public boolean isCacheStatisticsEnabled() {
		return cacheStatisticsEnabled;
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

	@Override
	public String toString() {
		return "TokenCacheConfiguration{" +
				"cacheDuration=" + cacheDuration +
				", cacheSize=" + cacheSize +
				", tokenExpirationDelta=" + tokenExpirationDelta +
				'}';
	}

	private static class DisabledCache extends TokenCacheConfiguration {

		private DisabledCache() {
			super(Duration.ZERO, 0, Duration.ZERO, false);
		}

		@Override
		public boolean isCacheDisabled() {
			return true;
		}
	}
}
