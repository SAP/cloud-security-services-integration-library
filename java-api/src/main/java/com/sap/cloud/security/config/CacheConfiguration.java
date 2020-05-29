package com.sap.cloud.security.config;

import java.time.Duration;

/**
 * Interface used for the configuration of caches.
 */
public interface CacheConfiguration {

	/**
	 * Returns the duration of the expire after write property of the cache. Cached
	 * elements are automatically invalidated after this fixed duration has elapsed.
	 *
	 * @return duration of expire after write.
	 */
	Duration getCacheDuration();

	/**
	 * Returns the number of elements the cache can hold.
	 *
	 * @return the size of the cache.
	 */
	int getCacheSize();

	/**
	 * Caching is disabled when this returns {@code true}.
	 *
	 * @return {@code true} if cache is disabled
	 */
	default boolean isCacheDisabled() {
		return false;
	}
}
