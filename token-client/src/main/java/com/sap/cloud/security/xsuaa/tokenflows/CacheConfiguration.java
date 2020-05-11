package com.sap.cloud.security.xsuaa.tokenflows;

import java.time.Duration;
import java.util.Objects;

/**
 * Data class to capture configuration options of caches.
 */
public class CacheConfiguration {

    /**
     * Creates the default cache configuration.
     */
    public static final CacheConfiguration DEFAULT = new CacheConfiguration(Duration.ofMinutes(15), 100);

    /**
     * Special cache configuration used to disable caching.
     */
    public static final CacheConfiguration CACHE_DISABLED = new CacheConfiguration(Duration.ZERO, 0);

    private final Duration expireAfterWrite;
    private final int cacheSize;

    public CacheConfiguration(Duration expireAfterWrite, int cacheSize) {
        this.expireAfterWrite = expireAfterWrite;
        this.cacheSize = cacheSize;
    }

    /**
     * Returns the expire after write property of the cache.
     * Cached elements are automatically invalidated after this fixed duration has elapsed.
     *
     * @return duration of expire after write.
     */
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

    @Override public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        CacheConfiguration that = (CacheConfiguration) o;
        return cacheSize == that.cacheSize &&
                Objects.equals(expireAfterWrite, that.expireAfterWrite);
    }

    @Override public int hashCode() {
        return Objects.hash(expireAfterWrite, cacheSize);
    }
}
