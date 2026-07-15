/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.cache;

import jakarta.annotation.Nonnull;
import java.time.Duration;
import java.util.Optional;

/**
 * A {@link SecurityCache} that never stores anything. Every {@link #get(Object)} returns
 * {@link Optional#empty()}; {@link #set(Object, Object, Duration)} is a no-op.
 *
 * <p>Useful for testing scenarios where caching should be disabled entirely without changing the
 * wiring, or as a documented way to opt out of caching in production.
 *
 * @since 4.1.0
 */
public final class NoOpSecurityCache<K, V> implements SecurityCache<K, V> {

  @Nonnull
  @Override
  public Optional<V> get(@Nonnull final K key) {
    return Optional.empty();
  }

  @Override
  public void set(@Nonnull final K key, @Nonnull final V value, final Duration ttl) {
    // no-op
  }

  @Override
  public void delete(@Nonnull final K key) {
    // no-op
  }

  @Override
  public void clear() {
    // no-op
  }
}
