/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.cache;

import com.sap.cloud.security.cache.CacheKeys;
import com.sap.cloud.security.cache.NoOpSecurityCache;
import com.sap.cloud.security.cache.SecurityCache;
import com.sap.cloud.security.token.Token;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Opt-in cache that memoizes the mapping <em>token string → decoded {@link Token}</em>.
 *
 * <p>Purpose: when many requests carry the same access token — e.g. a chatty micro-service that
 * validates a bearer on every hop — decoding the JWT (base64 decode + JSON parse + claim wiring)
 * is a small but repeated cost. Behind the {@link SecurityCache} SPI the cache can also be shared
 * across pods to survive rolling deploys and horizontal scaling.
 *
 * <h2>Design</h2>
 *
 * <ul>
 *   <li>Key: {@link CacheKeys#build(String, String)} with namespace {@code decode} over a SHA-256
 *       digest of the token string. The token itself is never used as a key so a leaked cache key
 *       list cannot be replayed.
 *   <li>Value: the token's original serialized form (its {@code TokenValue}). Storing the token
 *       string lets {@link Token#create(String)} rebuild an identical token on every hit —
 *       consistent with the codebase's token model and cheap to serialize / deserialize.
 *   <li>TTL: capped by {@code exp - now} so we never hand out an expired token. Entries with
 *       {@code exp} already in the past are not cached at all.
 * </ul>
 *
 * <h2>Failure Semantics</h2>
 *
 * Cache faults are always swallowed: a cache miss (or a broken cache) makes {@link
 * #getOrDecode(String, Function)} fall through to the caller-provided decoder. See {@link
 * SecurityCache} for the contract.
 *
 * <h2>Enabling</h2>
 *
 * The cache is <strong>off by default</strong>. Enable via
 * {@link TokenDecodeCacheConfiguration#enabled(Duration)}.
 *
 * <pre>{@code
 * SecurityCache<String, String> shared = new RedisSecurityCache(...);
 * TokenDecodeCache decodeCache = new TokenDecodeCache(
 *     shared, TokenDecodeCacheConfiguration.enabled(Duration.ofMinutes(5)));
 * Token token = decodeCache.getOrDecode(rawToken, Token::create);
 * }</pre>
 *
 * @since 4.1.0
 */
public final class TokenDecodeCache {

  private static final Logger LOGGER = LoggerFactory.getLogger(TokenDecodeCache.class);

  private final SecurityCache<String, String> cache;
  private final TokenDecodeCacheConfiguration configuration;
  private final Clock clock;

  /** Uses a system clock. */
  public TokenDecodeCache(
      @Nonnull final SecurityCache<String, String> cache,
      @Nonnull final TokenDecodeCacheConfiguration configuration) {
    this(cache, configuration, Clock.systemUTC());
  }

  /** Explicit-clock constructor, primarily for tests. */
  public TokenDecodeCache(
      @Nonnull final SecurityCache<String, String> cache,
      @Nonnull final TokenDecodeCacheConfiguration configuration,
      @Nonnull final Clock clock) {
    this.cache = configuration.isCacheDisabled() ? new NoOpSecurityCache<>() : cache;
    this.configuration = configuration;
    this.clock = clock;
  }

  /**
   * Returns a {@link Token} for the given raw token value, either from the cache or by running
   * the supplied {@code decoder}.
   *
   * @param tokenValue the raw JWT string
   * @param decoder function that turns the raw string into a {@link Token}; typically {@code
   *     Token::create}. May throw.
   * @return the decoded token
   */
  @Nullable
  public Token getOrDecode(
      @Nonnull final String tokenValue, @Nonnull final Function<String, Token> decoder) {
    if (configuration.isCacheDisabled()) {
      return decoder.apply(tokenValue);
    }
    final String key = keyFor(tokenValue);
    Optional<String> cached = safeGet(key);
    if (cached.isPresent()) {
      try {
        Token token = decoder.apply(cached.get());
        // Guard against a stale entry whose absolute exp has drifted past now while it was in
        // the cache but before this fetch — treat as a miss.
        if (token != null && !isExpired(token)) {
          return token;
        }
      } catch (final RuntimeException e) {
        LOGGER.warn("Cached token decode failed — refetching: {}", e.getMessage());
      }
    }

    Token decoded = decoder.apply(tokenValue);
    if (decoded != null) {
      Duration ttl = computeTtl(decoded);
      if (ttl != null) {
        safeSet(key, tokenValue, ttl);
      }
    }
    return decoded;
  }

  private static String keyFor(final String tokenValue) {
    return CacheKeys.build(CacheKeys.NAMESPACE_DECODE, tokenValue);
  }

  private Optional<String> safeGet(final String key) {
    try {
      return cache.get(key);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.get failed for decode entry: {}", e.getMessage());
      return Optional.empty();
    }
  }

  private void safeSet(final String key, final String value, final Duration ttl) {
    try {
      cache.set(key, value, ttl);
    } catch (final RuntimeException e) {
      LOGGER.warn("SecurityCache.set failed for decode entry: {}", e.getMessage());
    }
  }

  /**
   * Computes the effective TTL: min({@code exp - now}, configured cap). Returns {@code null} if the
   * token is already expired (or has no expiration claim).
   */
  @Nullable
  Duration computeTtl(final Token token) {
    Instant exp = token.getExpiration();
    if (exp == null) {
      return null;
    }
    Duration remaining = Duration.between(Instant.now(clock), exp);
    if (remaining.isZero() || remaining.isNegative()) {
      return null;
    }
    Duration cap = configuration.getCacheDuration();
    Duration ttl = remaining.compareTo(cap) < 0 ? remaining : cap;
    if (ttl.compareTo(Duration.ofSeconds(1)) < 0) {
      ttl = Duration.ofSeconds(1);
    }
    return ttl;
  }

  private boolean isExpired(final Token token) {
    Instant exp = token.getExpiration();
    return exp != null && !exp.isAfter(Instant.now(clock));
  }
}
