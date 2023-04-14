/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.CacheConfiguration;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nonnull;
import java.time.Duration;

/**
 *
 */
class TokenKeyCacheConfiguration implements CacheConfiguration {

	private static final TokenKeyCacheConfiguration DEFAULT = TokenKeyCacheConfiguration
			.getInstance(Duration.ofMinutes(10), 1000, false);

	private final Duration cacheDuration;
	private final int cacheSize;
	private final boolean cacheStatisticsEnabled;

	/**
	 * Creates a new {@link TokenKeyCacheConfiguration} instance with the given
	 * properties. See {@link CacheConfiguration#getCacheDuration()},
	 * {@link CacheConfiguration#getCacheSize()} and
	 * {@link CacheConfiguration#isCacheStatisticsEnabled()} for an explanation of
	 * the respective properties.
	 *
	 * @param cacheDuration
	 *            the cache duration property.
	 * @param cacheSize
	 *            the cache size property.
	 * @param cacheStatisticsEnabled
	 *            set to {@code true} if cache statists should be recorded
	 * @return a new {@link TokenKeyCacheConfiguration} instance.
	 */
	static TokenKeyCacheConfiguration getInstance(Duration cacheDuration, int cacheSize,
			boolean cacheStatisticsEnabled) {
		Assertions.assertNotNull(cacheDuration, "The cache duration write must not be null!");
		return new TokenKeyCacheConfiguration(cacheDuration, cacheSize, cacheStatisticsEnabled);
	}

	/**
	 * The default configuration for the token key cache. The default cache size is
	 * 1000. The default cache duration is 10 minutes. Cache statistics are not
	 * enabled.
	 *
	 * @return the default configuration
	 */
	static TokenKeyCacheConfiguration defaultConfiguration() {
		return DEFAULT;
	}

	private TokenKeyCacheConfiguration(Duration cacheDuration, int cacheSize, boolean cacheStatisticsEnabled) {
		this.cacheDuration = cacheDuration;
		this.cacheSize = cacheSize;
		this.cacheStatisticsEnabled = cacheStatisticsEnabled;
	}

	@Override
	@Nonnull
	public Duration getCacheDuration() {
		return cacheDuration;
	}

	@Override
	public int getCacheSize() {
		return cacheSize;
	}

	@Override
	public boolean isCacheStatisticsEnabled() {
		return cacheStatisticsEnabled;
	}
}
