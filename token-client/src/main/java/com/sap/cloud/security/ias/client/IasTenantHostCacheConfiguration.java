/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import jakarta.annotation.Nonnull;
import java.time.Duration;

/**
 * Immutable configuration for the {@link IasTenantHostResolver} subdomain cache and the BTP tenant
 * API request behavior.
 * <p>
 * Use {@link #builder()} to create a customized configuration, or {@link #defaultConfiguration()}
 * for sensible defaults (enabled, 15 minute TTL, max 1000 entries, full information lookup).
 * <p>
 * <h2>TTL and tenant moves</h2>
 *
 * <p>Subscriber tenants can be moved between zones. During the move window (up to one hour of
 * downtime) the old tenant location remains callable for up to a week. A TTL of 15 minutes is
 * therefore a safe default: within that window an already-resolved host is served from the cache,
 * and after it expires the next resolution observes the new location. Failures are never cached,
 * so a tenant move is picked up on the next resolution attempt.
 * <p>
 * Set {@link Builder#enabled(boolean)} to {@code false} to disable caching entirely; in that case
 * every {@link IasTenantHostResolver#resolve(String)} call will hit the BTP tenant API.
 */
public record IasTenantHostCacheConfiguration(
    boolean enabled, @Nonnull Duration ttl, long maxSize, boolean localInformationOnly) {

  /** Default cache entry TTL: 15 minutes. */
  public static final Duration DEFAULT_TTL = Duration.ofMinutes(15);

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

  /**
   * @return the default configuration: enabled, 15 minute TTL, max 1000 entries, full information
   *     lookup (IAS registry consulted)
   */
  public static IasTenantHostCacheConfiguration defaultConfiguration() {
    return builder().build();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private boolean enabled = true;
    private Duration ttl = DEFAULT_TTL;
    private long maxSize = 1000L;
    private boolean localInformationOnly = false;

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

    /**
     * Enables the {@code localInformationOnly} mode of the BTP tenant API: the tenant host is read
     * from the locally known information instead of performing a lookup in the IAS registry.
     * Useful when the registry lookup must be avoided (e.g. restricted network paths); the value
     * may be stale until the local information is refreshed.
     *
     * @param localInformationOnly {@code true} to pass {@code localInformationOnly=true} to the API
     * @return this builder.
     */
    public Builder localInformationOnly(boolean localInformationOnly) {
      this.localInformationOnly = localInformationOnly;
      return this;
    }

    public IasTenantHostCacheConfiguration build() {
      return new IasTenantHostCacheConfiguration(enabled, ttl, maxSize, localInformationOnly);
    }
  }
}
