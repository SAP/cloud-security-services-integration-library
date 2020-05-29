package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.CacheConfiguration;

import javax.annotation.Nonnull;

/**
 * Interface for components that manage a cache configured with
 * {@link CacheConfiguration}.
 */
public interface Cacheable {

	/**
	 * Provides the cache configuration of the component. Must not be null.
	 *
	 * @return the cache configuration
	 */
	@Nonnull
	CacheConfiguration getCacheConfiguration();

	/**
	 * Clears the cache of the component.
	 */
	void clearCache();
}
