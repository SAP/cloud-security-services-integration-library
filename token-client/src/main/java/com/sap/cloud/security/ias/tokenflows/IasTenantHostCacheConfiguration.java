/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.tokenflows;

import jakarta.annotation.Nonnull;
import java.time.Duration;

/**
 * Immutable configuration for the {@link IasTenantHostResolver} subdomain cache.
 * <p>
 * Use {@link #builder()} to create a customized configuration, or {@link #defaultConfiguration()}
 * for sensible defaults (enabled, 1h TTL, max 1000 entries).
 * <p>
 * Set {@link Builder#enabled(boolean)} to {@code false} to disable caching entirely; in that case
 * every {@link IasTenantHostResolver#resolve(String)} call will hit the BTP tenant API.
 */
public record IasTenantHostCacheConfiguration(boolean enabled, @Nonnull Duration ttl, long maxSize) {

	public IasTenantHostCacheConfiguration {
		if (ttl == null) {
			throw new IllegalArgumentException("ttl must not be null");
		}
		if (enabled && ttl.isNegative()) {
			throw new IllegalArgumentException("ttl must not be negative");
		}
		if (enabled && maxSize <= 0) {
			throw new IllegalArgumentException("maxSize must be positive");
		}
	}

	public static IasTenantHostCacheConfiguration defaultConfiguration() {
		return builder().build();
	}

	public static Builder builder() {
		return new Builder();
	}

	public static final class Builder {
		private boolean enabled = true;
		private Duration ttl = Duration.ofHours(1);
		private long maxSize = 1000L;

		private Builder() {
		}

		public Builder enabled(boolean enabled) {
			this.enabled = enabled;
			return this;
		}

		public Builder ttl(@Nonnull Duration ttl) {
			this.ttl = ttl;
			return this;
		}

		public Builder maxSize(long maxSize) {
			this.maxSize = maxSize;
			return this;
		}

		public IasTenantHostCacheConfiguration build() {
			return new IasTenantHostCacheConfiguration(enabled, ttl, maxSize);
		}
	}
}