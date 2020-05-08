package com.sap.cloud.security.xsuaa.tokenflows;

import java.time.Duration;
import java.util.Objects;

public class CacheConfiguration {

    public static final CacheConfiguration DEFAULT = new CacheConfiguration(Duration.ofMinutes(15), 100);
    public static final CacheConfiguration NO_CACHE = new CacheConfiguration(Duration.ZERO, 0);

    private final Duration expireAfterWrite;
    private final int cacheSize;

    public CacheConfiguration(Duration expireAfterWrite, int cacheSize) {
        this.expireAfterWrite = expireAfterWrite;
        this.cacheSize = cacheSize;
    }

    public Duration getExpireAfterWrite() {
        return expireAfterWrite;
    }

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
