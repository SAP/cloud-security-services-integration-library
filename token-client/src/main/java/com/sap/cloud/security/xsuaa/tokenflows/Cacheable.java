package com.sap.cloud.security.xsuaa.tokenflows;

import javax.annotation.Nonnull;

public interface Cacheable {

    @Nonnull
    CacheConfiguration getCacheConfiguration();

    void clearCache();
}
