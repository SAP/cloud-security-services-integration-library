package com.sap.cloud.security.xsuaa.tokenflows;

import org.checkerframework.checker.nullness.qual.NonNull;

public interface Cacheable {

    @NonNull
    CacheConfiguration getCacheConfiguration();

    void clearCache();
}
