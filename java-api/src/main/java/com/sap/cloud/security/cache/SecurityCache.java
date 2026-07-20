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
 * Service Provider Interface for pluggable cache implementations used by the SAP Cloud Security
 * client libraries.
 *
 * <p>Implementations may be backed by an in-memory store (default) or by a distributed cache such
 * as Redis, Hazelcast, or any store you can adapt behind the four methods below. See the
 * {@code CaffeineSecurityCache} (in-memory) and {@code SpringCacheSecurityCache} (Spring
 * {@code CacheManager}) adapters for reference. Any other backend is a copy-pasteable
 * implementation of this interface — see the project README for snippets.
 *
 * <h2>Contract</h2>
 *
 * The library treats every cache operation as best-effort. A cache failure must never cause a
 * token fetch, a JWKS retrieval, or a token validation to fail. Implementations therefore
 * <strong>must not</strong> throw exceptions from any of the methods declared here:
 *
 * <ul>
 *   <li>{@link #get(Object)} — on any error (network, timeout, deserialization) return
 *       {@link Optional#empty()} and log at WARN level. The caller will treat it as a cache miss
 *       and fetch the value from source.
 *   <li>{@link #set(Object, Object, Duration)} — on any error log at WARN level and return without
 *       throwing. The value is not cached; the next call will refetch.
 *   <li>{@link #delete(Object)} — on any error log at WARN level and return without throwing.
 *   <li>{@link #clear()} — on any error log at WARN level and return without throwing.
 * </ul>
 *
 * <p>Timeouts (connect/read) are the responsibility of the concrete adapter and should be small
 * enough (100-500ms) that a slow distributed cache does not become a bottleneck.
 *
 * <h2>Thread Safety</h2>
 *
 * Implementations must be safe for concurrent use by multiple threads.
 *
 * <h2>Consistency with the Node.js xssec library</h2>
 *
 * The method names {@code get} / {@code set} / {@code delete} / {@code clear} mirror the Node.js
 * xssec cache SPI so that documentation can be shared across both libraries.
 *
 * @param <K> the key type — the library uses {@link String} internally
 * @param <V> the value type — the library uses {@link String} (raw JSON) internally
 * @since 4.1.0
 */
public interface SecurityCache<K, V> {

  /**
   * Returns the value for {@code key} if it is present in the cache, otherwise
   * {@link Optional#empty()}.
   *
   * <p>Must not throw. Any error (network failure, timeout, deserialization) must be handled
   * internally and result in an empty {@code Optional}.
   *
   * @param key the cache key, never {@code null}
   * @return the cached value, or {@link Optional#empty()} if absent or on error
   */
  @Nonnull
  Optional<V> get(@Nonnull K key);

  /**
   * Stores {@code value} for {@code key} with the given time-to-live.
   *
   * <p>Must not throw. Any error must be handled internally.
   *
   * @param key the cache key, never {@code null}
   * @param value the value to store, never {@code null}
   * @param ttl the time-to-live for this entry; {@code null} means "use adapter default"
   */
  void set(@Nonnull K key, @Nonnull V value, Duration ttl);

  /**
   * Removes the entry for {@code key} from the cache. No-op if the key was not present.
   *
   * <p>Must not throw.
   *
   * @param key the cache key, never {@code null}
   */
  void delete(@Nonnull K key);

  /**
   * Removes all entries owned by this library from the cache.
   *
   * <p>Implementations backed by a shared store <strong>should</strong> restrict this to entries
   * with the library's key prefix (see {@code CacheKeys}) rather than flushing the entire store.
   *
   * <p>Must not throw.
   */
  void clear();
}
