/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.x509.Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread-local storage for security-related context information.
 *
 * <p>This class provides static methods to access and manage security tokens, certificates, and
 * service plans on a per-thread basis. Each thread maintains its own isolated context, making this
 * class safe for use in multi-threaded environments such as web servers handling concurrent
 * requests.
 *
 * <p><b>Core Features:</b>
 *
 * <ul>
 *   <li><b>Token Management:</b> Store and retrieve access tokens, ID tokens, and XSUAA tokens
 *   <li><b>Automatic Token Resolution:</b> Lazy-load tokens via registered extensions when needed
 *   <li><b>Token Caching:</b> Cache resolved tokens with expiration checking (5-minute buffer)
 *   <li><b>Certificate Storage:</b> Store X.509 client certificates for mTLS scenarios
 *   <li><b>Service Plan Tracking:</b> Store Identity Authentication Service plan information
 * </ul>
 *
 * <p><b>Thread-Local Storage:</b> All security context data is stored in a single {@link
 * ThreadLocal} instance, ensuring thread isolation and memory efficiency. Each thread gets its own
 * {@code ContextHolder} containing all security-related state. This design:
 *
 * <ul>
 *   <li>Eliminates the need for multiple {@link ThreadLocal} fields (reduces memory overhead)
 *   <li>Improves cache locality by grouping related data in one object
 *   <li>Simplifies cleanup with {@link #clearContext()} removing all data in one call
 * </ul>
 *
 * <p><b>Token Extension System:</b> The class supports pluggable token resolution via extensions:
 *
 * <ul>
 *   <li>{@link IdTokenExtension} — Resolves ID tokens (e.g., via OAuth2 user token flow)
 *   <li>{@link XsuaaTokenExtension} — Resolves XSUAA tokens (e.g., via IAS-to-XSUAA exchange)
 * </ul>
 *
 * Extensions are registered globally but operate on thread-local context. Resolved tokens are
 * automatically cached until expiration.
 *
 * <p><b>Usage Example:</b>
 *
 * <pre>{@code
 * // 1. Register extensions (once at application startup)
 * SecurityContext.registerIdTokenExtension(new DefaultIdTokenExtension(tokenService, iasConfig));
 * SecurityContext.registerXsuaaTokenExtension(new DefaultXsuaaTokenExtension(tokenService, xsuaaConfig));
 *
 * // 2. Set the initial token (e.g., in authentication filter)
 * Token accessToken = parseFromAuthorizationHeader(request);
 * SecurityContext.setToken(accessToken);
 *
 * // 3. Access tokens in business logic
 * Token idToken = SecurityContext.getIdToken();  // Automatically resolved if not cached
 * Token xsuaaToken = SecurityContext.getXsuaaToken();  // Automatically exchanged if needed
 *
 * // 4. Clean up after request (e.g., in filter's finally block)
 * SecurityContext.clear();  // or SecurityContext.clearContext() for complete cleanup
 * }</pre>
 *
 * <p><b>Token Lifecycle:</b>
 *
 * <ol>
 *   <li><b>Initial Token:</b> Set via {@link #setToken(Token)} (typically from HTTP Authorization
 *       header)
 *   <li><b>Caching:</b> {@link #getIdToken()} and {@link #getXsuaaToken()} cache resolved tokens
 *   <li><b>Expiration:</b> Cached tokens are checked for expiration (5-minute safety buffer)
 *   <li><b>Re-resolution:</b> Expired tokens trigger automatic re-resolution via extensions
 *   <li><b>Cleanup:</b> {@link #clear()} or {@link #clearContext()} removes all tokens
 * </ol>
 *
 * <p><b>Memory Management:</b> When using thread pools (e.g., servlet containers), always call
 * {@link #clearContext()} at the end of request processing to prevent memory leaks. Thread pools
 * reuse threads, so stale context data can accumulate if not cleaned up properly.
 *
 * @see Token
 * @see AccessToken
 * @see IdTokenExtension
 * @see XsuaaTokenExtension
 */
public class SecurityContext {
  private static final Logger LOGGER = LoggerFactory.getLogger(SecurityContext.class);

  // Single ThreadLocal holding all context data
  private static final ThreadLocal<ContextHolder> contextStorage =
      ThreadLocal.withInitial(ContextHolder::new);

  // Global extensions (not thread-specific)
  private static IdTokenExtension idTokenExtension;
  private static XsuaaTokenExtension xsuaaTokenExtension;

  private SecurityContext() {}

  /**
   * Internal holder for all thread-local context data. Each thread gets its own instance via
   * ThreadLocal.
   *
   * <p>This class consolidates all security context fields into a single object to minimize
   * ThreadLocal overhead and improve cache locality. It is package-private to support testing via
   * reflection.
   */
  private static class ContextHolder {
    /** Current access token (may be overwritten during request processing). */
    Token token;

    /** Cached ID token (resolved lazily via {@link IdTokenExtension}). */
    Token idToken;

    /** Cached XSUAA token (resolved lazily via {@link XsuaaTokenExtension}). */
    Token xsuaaToken;

    /** Original token set at the start of request (never overwritten). */
    Token initialToken;

    /** Client X.509 certificate for mTLS scenarios. */
    Certificate certificate;

    /** Identity Authentication Service plans associated with the request. */
    List<String> servicePlans;

    /**
     * Checks if a token is valid (non-null and not expired).
     *
     * <p>Expiration is checked with a 5-minute safety buffer to prevent using tokens that are about
     * to expire during request processing.
     *
     * @param token the token to check
     * @return {@code true} if the token is valid, {@code false} otherwise
     */
    boolean isTokenValid(Token token) {
      return token != null
          && token.getExpiration() != null
          && token.getExpiration().minus(5, ChronoUnit.MINUTES).isAfter(Instant.now());
    }
  }

  /**
   * Returns the context holder for the current thread.
   *
   * <p>This method provides internal access to the thread-local storage. A new {@code
   * ContextHolder} is automatically created if this is the first access from the current thread.
   *
   * @return the context holder for the current thread (never {@code null})
   */
  private static ContextHolder getContext() {
    return contextStorage.get();
  }

  /**
   * Sets the access token for the current thread's security context.
   *
   * <p>This method performs the following actions:
   *
   * <ul>
   *   <li>Stores the token as the current access token
   *   <li>Stores the token as the initial token (preserves original authentication)
   *   <li>Clears any cached ID token (forces re-resolution on next {@link #getIdToken()} call)
   * </ul>
   *
   * <p><b>Typical Usage:</b> Called by authentication filters/interceptors after extracting the
   * token from the HTTP Authorization header. The token should be validated before setting it in
   * the context.
   *
   * @param token the access token to store (may be {@code null} to clear the token)
   */
  public static void setToken(Token token) {
    LOGGER.debug(
        "Sets token of service {} to SecurityContext (thread-locally).",
        token != null ? token.getService() : "null");
    ContextHolder ctx = getContext();
    ctx.token = token;
    ctx.initialToken = token;
    ctx.idToken = null; // Clear cached ID token
  }

  /**
   * Overwrites the current access token without affecting the initial token.
   *
   * <p>This method is typically used to cache exchanged tokens (e.g., after IAS-to-XSUAA token
   * exchange) while preserving the original token in {@link #getInitialToken()}.
   *
   * <p><b>Difference from {@link #setToken(Token)}:</b>
   *
   * <ul>
   *   <li>{@code setToken()} — Updates both current and initial token
   *   <li>{@code overwriteToken()} — Updates only current token, preserves initial token
   * </ul>
   *
   * @param token the token to store as the current token (may be {@code null})
   */
  public static void overwriteToken(Token token) {
    LOGGER.debug(
        "Overwrites token of service {} in SecurityContext (thread-locally).",
        token != null ? token.getService() : "null");
    getContext().token = token;
  }

  /**
   * Returns the current access token for the current thread.
   *
   * <p>This returns the token last set via {@link #setToken(Token)} or {@link
   * #overwriteToken(Token)}. It may differ from {@link #getInitialToken()} if token exchange has
   * occurred.
   *
   * @return the current access token, or {@code null} if none is set
   */
  @Nullable
  public static Token getToken() {
    return getContext().token;
  }

  /**
   * Returns the initial access token for the current thread.
   *
   * <p>This returns the original token set via {@link #setToken(Token)}, even if {@link
   * #overwriteToken(Token)} was called later. Use this to access the original authentication token
   * after token exchanges.
   *
   * @return the initial access token, or {@code null} if none was set
   */
  @Nullable
  public static Token getInitialToken() {
    return getContext().initialToken;
  }

  /**
   * Returns the current access token as an {@link AccessToken}, if applicable.
   *
   * <p>This is a convenience method that performs type checking and casting. It returns {@code
   * null} if the current token is not an {@link AccessToken} instance (e.g., if it's an ID token).
   *
   * @return the current token as {@link AccessToken}, or {@code null} if not applicable
   */
  @Nullable
  public static AccessToken getAccessToken() {
    Token token = getContext().token;
    return token instanceof AccessToken ? (AccessToken) token : null;
  }

  /**
   * Removes the current access token from the security context.
   *
   * <p>This does not clear the initial token. Use {@link #clearInitialToken()} separately if
   * needed. Subsequent calls to {@link #getToken()} will return {@code null} until a new token is
   * set.
   */
  public static void clearToken() {
    ContextHolder ctx = getContext();
    if (ctx.token != null) {
      LOGGER.debug(
          "Token of service {} removed from SecurityContext (thread-locally).",
          ctx.token.getService());
      ctx.token = null;
    }
  }

  /**
   * Removes the initial access token from the security context.
   *
   * <p>This does not clear the current token. Use {@link #clearToken()} separately if needed.
   * Subsequent calls to {@link #getInitialToken()} will return {@code null}.
   */
  public static void clearInitialToken() {
    ContextHolder ctx = getContext();
    if (ctx.initialToken != null) {
      LOGGER.debug(
          "Initial token of service {} removed from SecurityContext (thread-locally).",
          ctx.initialToken.getService());
      ctx.initialToken = null;
    }
  }

  /**
   * Retrieves the ID token associated with the current context.
   *
   * <p>This method implements lazy-loading and caching:
   *
   * <ol>
   *   <li>Returns cached ID token if it exists and is valid (expiration &gt; 5 minutes in future)
   *   <li>If cached token is expired or missing, clears it from cache
   *   <li>If {@link IdTokenExtension} is registered, calls {@link
   *       IdTokenExtension#resolveIdToken()}
   *   <li>Caches the resolved token for subsequent calls
   *   <li>Returns the resolved token (or {@code null} if resolution failed)
   * </ol>
   *
   * <p><b>Extension Requirement:</b> Automatic resolution requires registering an {@link
   * IdTokenExtension} via {@link #registerIdTokenExtension(IdTokenExtension)}. Without an
   * extension, this method only returns previously cached tokens.
   *
   * @return the ID token, or {@code null} if:
   *     <ul>
   *       <li>No extension is registered
   *       <li>Token resolution fails
   *       <li>No access token is available for token exchange
   *     </ul>
   *
   * @see IdTokenExtension#resolveIdToken()
   * @see #registerIdTokenExtension(IdTokenExtension)
   */
  @Nullable
  public static Token getIdToken() {
    ContextHolder ctx = getContext();
    if (ctx.isTokenValid(ctx.idToken)) {
      return ctx.idToken;
    }
    ctx.idToken = null;
    if (idTokenExtension != null) {
      ctx.idToken = idTokenExtension.resolveIdToken();
    }
    return ctx.idToken;
  }

  /**
   * Removes the cached ID token from the security context.
   *
   * <p>This forces re-resolution on the next {@link #getIdToken()} call if an {@link
   * IdTokenExtension} is registered. Use this to invalidate cached tokens when needed.
   */
  public static void clearIdToken() {
    ContextHolder ctx = getContext();
    if (ctx.idToken != null) {
      LOGGER.debug("ID token removed from SecurityContext (thread-locally).");
      ctx.idToken = null;
    }
  }

  /**
   * Retrieves the XSUAA token associated with the current context.
   *
   * <p>This method implements lazy-loading, caching, and automatic token exchange:
   *
   * <ol>
   *   <li>Returns cached XSUAA token if it exists and is valid (expiration &gt; 5 minutes in
   *       future)
   *   <li>If cached token is expired or missing, clears it from cache
   *   <li>If {@link XsuaaTokenExtension} is registered, calls {@link
   *       XsuaaTokenExtension#resolveXsuaaToken()}
   *   <li>Caches the resolved/exchanged token for subsequent calls
   *   <li>Returns the resolved token (or {@code null} if resolution failed)
   * </ol>
   *
   * <p><b>Hybrid Authentication (Level 0 Migration):</b> In hybrid scenarios where IAS tokens are
   * received but XSUAA authorization is still used, this method automatically exchanges IAS tokens
   * to XSUAA format via the registered {@link XsuaaTokenExtension}. The exchanged token is cached
   * to avoid repeated exchanges.
   *
   * <p><b>Extension Requirement:</b> Automatic exchange requires:
   *
   * <ul>
   *   <li>Registering a {@link XsuaaTokenExtension} via {@link
   *       #registerXsuaaTokenExtension(XsuaaTokenExtension)}
   *   <li>Proper Cloud Foundry configuration ({@code xsuaa-cross-consumption: true})
   * </ul>
   *
   * Without an extension, this method only returns previously cached XSUAA tokens.
   *
   * @return the XSUAA token, or {@code null} if:
   *     <ul>
   *       <li>No extension is registered
   *       <li>Token exchange fails (network error, invalid configuration, etc.)
   *       <li>No source token is available for exchange
   *     </ul>
   *
   * @see XsuaaTokenExtension#resolveXsuaaToken()
   * @see #registerXsuaaTokenExtension(XsuaaTokenExtension)
   */
  @Nullable
  public static Token getXsuaaToken() {
    ContextHolder ctx = getContext();
    if (ctx.isTokenValid(ctx.xsuaaToken)) {
      return ctx.xsuaaToken;
    }
    ctx.xsuaaToken = null;
    if (xsuaaTokenExtension != null) {
      ctx.xsuaaToken = xsuaaTokenExtension.resolveXsuaaToken();
    }
    return ctx.xsuaaToken;
  }

  /**
   * Removes the cached XSUAA token from the security context.
   *
   * <p>This forces re-resolution/exchange on the next {@link #getXsuaaToken()} call if a {@link
   * XsuaaTokenExtension} is registered. Use this to invalidate cached tokens when needed.
   */
  public static void clearXsuaaToken() {
    ContextHolder ctx = getContext();
    if (ctx.xsuaaToken != null) {
      LOGGER.debug("XSUAA token removed from SecurityContext (thread-locally).");
      ctx.xsuaaToken = null;
    }
  }

  /**
   * Returns the X.509 client certificate for the current thread.
   *
   * <p>This is used in mutual TLS (mTLS) scenarios where the client authenticates via certificate
   * instead of (or in addition to) JWT tokens.
   *
   * @return the client certificate, or {@code null} if none is set
   */
  @Nullable
  public static Certificate getClientCertificate() {
    return getContext().certificate;
  }

  /**
   * Sets the X.509 client certificate for the current thread's security context.
   *
   * <p>This is typically called by authentication filters/interceptors that extract the certificate
   * from the HTTP request (e.g., from the {@code javax.servlet.request.X509Certificate} attribute).
   *
   * @param certificate the client certificate to store (may be {@code null} to clear it)
   */
  public static void setClientCertificate(Certificate certificate) {
    LOGGER.debug("Sets certificate to SecurityContext (thread-locally). {}", certificate);
    getContext().certificate = certificate;
  }

  /** Removes the client certificate from the security context. */
  private static void clearCertificate() {
    ContextHolder ctx = getContext();
    if (ctx.certificate != null) {
      LOGGER.debug("Certificate removed from SecurityContext (thread-locally).");
      ctx.certificate = null;
    }
  }

  /**
   * Returns the Identity Authentication Service plans associated with the current request.
   *
   * <p>Service plans indicate which IAS features/capabilities are available for the current
   * user/tenant. This information is typically extracted from custom HTTP headers in multi-tenant
   * scenarios.
   *
   * @return the list of service plans, or {@code null} if none are set
   */
  @Nullable
  public static List<String> getServicePlans() {
    return getContext().servicePlans;
  }

  /**
   * Parses and stores Identity Authentication Service plans from a comma-separated header value.
   *
   * <p><b>Expected Format:</b> {@code "plan1", "plan2", "plan3"} <br>
   * Plans are extracted by splitting on commas and removing surrounding quotes.
   *
   * @param servicePlansHeader the comma-separated service plans header value (must not be {@code
   *     null})
   * @throws NullPointerException if {@code servicePlansHeader} is {@code null}
   */
  public static void setServicePlans(String servicePlansHeader) {
    String[] planParts = servicePlansHeader.trim().split("\\s*,\\s*");

    List<String> plans =
        Arrays.stream(planParts)
            .map(plan -> plan.substring(1, plan.length() - 1))
            .collect(Collectors.toList());

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Sets Identity Service Plan {} to SecurityContext (thread-locally).", plans);
    }

    getContext().servicePlans = plans;
  }

  /** Removes the service plans from the security context. */
  public static void clearServicePlans() {
    ContextHolder ctx = getContext();
    if (ctx.servicePlans != null && !ctx.servicePlans.isEmpty()) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug(
            "Service plans {} removed from SecurityContext (thread-locally).", ctx.servicePlans);
      }
      ctx.servicePlans = null;
    }
  }

  /**
   * Registers a global {@link IdTokenExtension} for automatic ID token resolution.
   *
   * <p>The extension is called by {@link #getIdToken()} when no valid cached ID token exists. Only
   * one extension can be registered at a time; calling this method multiple times overwrites the
   * previous extension.
   *
   * <p><b>Registration Timing:</b> Typically called once during application startup. However,
   * per-request registration is also supported for scenarios where dependency injection causes
   * circular bean initialization issues. Extensions are stateless, so overwriting the previous
   * extension is safe.
   *
   * @param ext the ID token extension to register (may be {@code null} to unregister)
   * @see IdTokenExtension#resolveIdToken()
   * @see #getIdToken()
   */
  public static void registerIdTokenExtension(IdTokenExtension ext) {
    idTokenExtension = ext;
  }

  /**
   * Registers a global {@link XsuaaTokenExtension} for automatic XSUAA token resolution/exchange.
   *
   * <p>The extension is called by {@link #getXsuaaToken()} when no valid cached XSUAA token exists.
   * Only one extension can be registered at a time; calling this method multiple times overwrites
   * the previous extension.
   *
   * <p><b>Registration Timing:</b> Typically called once during application startup. However,
   * per-request registration is also supported for scenarios where dependency injection causes
   * circular bean initialization issues. Extensions are stateless, so overwriting the previous
   * extension is safe.
   *
   * @param ext the XSUAA token extension to register (may be {@code null} to unregister)
   * @see XsuaaTokenExtension#resolveXsuaaToken()
   * @see #getXsuaaToken()
   */
  public static void registerXsuaaTokenExtension(XsuaaTokenExtension ext) {
    xsuaaTokenExtension = ext;
  }

  /**
   * Clears all stored data for the current thread.
   *
   * <p>This method clears:
   *
   * <ul>
   *   <li>Client certificate ({@link #clearCertificate()})
   *   <li>Current access token ({@link #clearToken()})
   *   <li>Cached ID token ({@link #clearIdToken()})
   *   <li>Cached XSUAA token ({@link #clearXsuaaToken()})
   *   <li>Initial access token ({@link #clearInitialToken()})
   *   <li>Service plans ({@link #clearServicePlans()})
   * </ul>
   *
   * <p><b>When to Use:</b> Call this at the end of request processing (e.g., in a servlet filter's
   * {@code finally} block) to prevent data leakage between requests when using thread pools.
   *
   * <p><b>Note:</b> This does not remove the {@code ContextHolder} itself from {@link ThreadLocal}.
   * Use {@link #clearContext()} for complete cleanup if needed.
   */
  public static void clear() {
    clearCertificate();
    clearToken();
    clearIdToken();
    clearXsuaaToken();
    clearInitialToken();
    clearServicePlans();
  }

  /**
   * Removes the entire context holder for the current thread.
   *
   * <p>This performs complete ThreadLocal cleanup by removing the {@code ContextHolder} instance.
   * Use this to prevent memory leaks in thread pool environments where threads are reused.
   *
   * <p><b>Difference from {@link #clear()}:</b>
   *
   * <ul>
   *   <li>{@code clear()} — Nulls out all fields but keeps the {@code ContextHolder} instance
   *   <li>{@code clearContext()} — Removes the entire {@code ContextHolder} from ThreadLocal
   *       storage
   * </ul>
   *
   * <p><b>Best Practice:</b> Call this in the {@code finally} block of your request handling code:
   *
   * <pre>{@code
   * try {
   *     // Process request
   *     SecurityContext.setToken(token);
   *     // ... business logic ...
   * } finally {
   *     SecurityContext.clearContext();  // Complete cleanup
   * }
   * }</pre>
   */
  public static void clearContext() {
    contextStorage.remove();
    LOGGER.debug("Entire SecurityContext removed (thread-locally).");
  }
}