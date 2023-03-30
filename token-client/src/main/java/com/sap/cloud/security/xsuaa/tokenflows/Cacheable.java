/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.CacheConfiguration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

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

	/**
	 * This returns an implementation specific statistics object if the underlying
	 * cache supports it and cache statistics have been enabled in the
	 * {@link CacheConfiguration}.
	 *
	 * Use with care. The type of the statistics object might change in later
	 * versions.
	 *
	 * @return the cache statistics object.
	 */
	@Nullable
	Object getCacheStatistics();
}
