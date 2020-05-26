package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nonnull;
import java.time.Duration;
import java.util.Objects;

/**
 * Data class to capture configuration options of token caches.
 */
public class CacheConfiguration {

	/**
	 * Creates the default cache configuration.
	 */
	public static final CacheConfiguration DEFAULT = new CacheConfiguration(Duration.ofMinutes(10), 1000,
			Duration.ofSeconds(30));

	/**
	 * Special cache configuration used to disable caching.
	 */
	public static final CacheConfiguration CACHE_DISABLED = new CacheConfiguration(Duration.ZERO, 0, Duration.ZERO);

	private final Duration expireAfterWrite;
	private final int cacheSize;
	private final Duration tokenExpirationDelta;

	/**
	 * Creates a new {@link CacheConfiguration} instance with the given properties.
	 * See {@link CacheConfiguration#getExpireAfterWrite()},
	 * {@link CacheConfiguration#getCacheSize()} and
	 * {@link CacheConfiguration#getTokenExpirationDelta()} for a explanation of the
	 * respective properties.
	 *
	 * @param expireAfterWrite
	 *            the expire after write cache property.
	 * @param cacheSize
	 *            the cache size property.
	 * @param tokenExpirationDelta
	 *            the token expiration delta.
	 * @return a new {@link CacheConfiguration} instance.
	 */
	public static CacheConfiguration getInstance(@Nonnull Duration expireAfterWrite, int cacheSize,
			@Nonnull Duration tokenExpirationDelta) {
		Assertions.assertNotNull(expireAfterWrite, "Expire after write must not be null!");
		return new CacheConfiguration(expireAfterWrite, cacheSize, tokenExpirationDelta);
	}

	private CacheConfiguration(Duration expireAfterWrite, int cacheSize, Duration tokenExpirationDelta) {
		this.expireAfterWrite = expireAfterWrite;
		this.cacheSize = cacheSize;
		this.tokenExpirationDelta = tokenExpirationDelta;
	}

	/**
	 * Returns the expire after write property of the cache. Cached elements are
	 * automatically invalidated after this fixed duration has elapsed.
	 *
	 * @return duration of expire after write.
	 */
	@Nonnull
	public Duration getExpireAfterWrite() {
		return expireAfterWrite;
	}

	/**
	 * Returns the number of elements the cache can hold.
	 *
	 * @return the size of the cache.
	 */
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
		CacheConfiguration that = (CacheConfiguration) o;
		return cacheSize == that.cacheSize &&
				Objects.equals(expireAfterWrite, that.expireAfterWrite);
	}

	@Override
	public int hashCode() {
		return Objects.hash(expireAfterWrite, cacheSize);
	}
}
