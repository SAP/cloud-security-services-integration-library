/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.x509.Certificate;
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
 *   <li><b>Token Caching:</b> Cache resolved tokens
 *   <li><b>Certificate Storage:</b> Store X.509 client certificates for mTLS scenarios
 *   <li><b>Service Plan Tracking:</b> Store Identity Authentication Service plan information
 * </ul>
 *
 * <p><b>Thread-Local Storage:</b> All security context data is stored in a {@link ThreadLocal}
 * instance, ensuring thread isolation. Each thread gets its own {@code SecurityContext} containing
 * all security-related state. This design:
 *
 * <ul>
 *   <li>Eliminates the need for multiple {@link ThreadLocal} fields (reduces memory overhead)
 *   <li>Improves cache locality by grouping related data in one object
 *   <li>Simplifies cleanup with {@link #clear()} removing all data in one call
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
 * SecurityContext.clear();  // Clears all tokens, certificate, and service plans
 * }</pre>
 *
 * <p><b>Token Lifecycle:</b>
 *
 * <ol>
 *   <li><b>Initial Token:</b> Set via {@link #setToken(Token)} (typically from HTTP Authorization
 *       header)
 *   <li><b>Caching:</b> {@link #getIdToken()} and {@link #getXsuaaToken()} cache resolved tokens
 *   <li><b>Re-resolution:</b> Expired tokens trigger automatic re-resolution via extensions
 *   <li><b>Cleanup:</b> {@link #clear()} or {@link #clearContext()} removes all tokens
 * </ol>
 *
 * <p><b>Memory Management:</b> When using thread pools (e.g., servlet containers), always call
 * {@link #clear()} or {@link #clearContext()} at the end of request processing to prevent memory
 * leaks. Thread pools reuse threads, so stale context data can accumulate if not cleaned up
 * properly.
 *
 * <p><b>Cross-Thread Usage:</b> For advanced scenarios like asynchronous token exchange, you can
 * capture the context and pass it to other threads:
 *
 * <pre>{@code
 * SecurityContext ctx = SecurityContext.get();
 * CompletableFuture.supplyAsync(() -> {
 *     Token exchangedToken = tokenExchange.exchange(ctx.token);
 *     ctx.updateToken(exchangedToken);  // Preserves other context properties
 *     return callApi(exchangedToken);
 * });
 * }</pre>
 *
 * @see Token
 * @see AccessToken
 * @see IdTokenExtension
 * @see XsuaaTokenExtension
 */
public class SecurityContext {
  private static final Logger LOGGER = LoggerFactory.getLogger(SecurityContext.class);

  /**
   * Thread-local storage for security context instances.
   *
   * <p>Each thread gets its own isolated {@code SecurityContext} instance. The {@code withInitial}
   * supplier ensures that calling {@link #get()} always returns a non-null instance.
   */
  private static final ThreadLocal<SecurityContext> contextStorage =
      ThreadLocal.withInitial(SecurityContext::new);

  /**
   * The current access token for this thread.
   *
   * <p>This is typically the JWT from the {@code Authorization: Bearer <token>} header. It may be
   * either an IAS token or XSUAA token depending on the authentication provider.
   */
  Token token;

  /**
   * Cached ID token for this thread.
   *
   * <p>Lazily resolved via {@link IdTokenExtension} when {@link #getIdToken()} is called. Cached
   * until expiration (checked with 5-minute buffer).
   */
  Token idToken;

  /**
   * Cached XSUAA token for this thread.
   *
   * <p>In hybrid IAS/XSUAA scenarios, this contains the XSUAA token exchanged from the IAS token.
   * Lazily resolved via {@link XsuaaTokenExtension} when {@link #getXsuaaToken()} is called.
   */
  Token xsuaaToken;

  /**
   * The original access token set via {@link #setToken(Token)}.
   *
   * <p>Preserved even if {@link #token} is replaced via {@link #updateToken(Token)}. Use {@link
   * #getInitialToken()} to access the original authentication token after token exchanges.
   */
  Token initialToken;

  /**
   * X.509 client certificate for this thread (used in mTLS scenarios).
   *
   * <p>Set via {@link #setClientCertificate(Certificate)} and typically extracted from the HTTP
   * request's {@code javax.servlet.request.X509Certificate} attribute.
   */
  Certificate certificate;

  /**
   * Identity Authentication Service plans for the current request.
   *
   * <p>Extracted from the {@code X-Identity-Service-Plan} (or similar) HTTP header in multi-tenant
   * scenarios. Indicates which IAS features are available for the current user/tenant.
   */
  List<String> servicePlans;

  /**
   * Global ID token extension (shared across all threads).
   *
   * <p>Registered via {@link #registerIdTokenExtension(IdTokenExtension)}. Used by {@link
   * #getIdToken()} to resolve ID tokens when not cached.
   */
  private static IdTokenExtension idTokenExtension;

  /**
   * Global XSUAA token extension (shared across all threads).
   *
   * <p>Registered via {@link #registerXsuaaTokenExtension(XsuaaTokenExtension)}. Used by {@link
   * #getXsuaaToken()} to exchange IAS tokens to XSUAA format in hybrid scenarios.
   */
  private static XsuaaTokenExtension xsuaaTokenExtension;

  /**
   * Package-private constructor to allow instantiation for cross-thread passing.
   *
   * <p>This allows capturing the context via {@link #get()} and passing it to other threads for
   * correlation or token exchange scenarios.
   */
  SecurityContext() {}

  /**
   * Returns the {@code SecurityContext} for the current thread.
   *
   * <p>This method never returns {@code null}—if no context exists for the current thread, a new
   * empty instance is created automatically.
   *
   * <p><b>Cross-Thread Usage:</b> The returned instance can be passed to other threads or stored in
   * event payloads for correlation:
   *
   * <pre>{@code
   * SecurityContext ctx = SecurityContext.get();
   * CompletableFuture.supplyAsync(() -> {
   *     Token t = ctx.token;  // Access token from captured context
   *     return process(t);
   * });
   * }</pre>
   *
   * @return the current thread's security context (never {@code null})
   */
  public static SecurityContext get() {
    return contextStorage.get();
  }

  /**
   * Returns the current access token for this thread.
   *
   * <p>This returns the token set via {@link #setToken(Token)} or replaced via {@link
   * #updateToken(Token)}. In hybrid IAS/XSUAA scenarios, this may be either:
   *
   * <ul>
   *   <li>IAS token (from the HTTP Authorization header)
   *   <li>XSUAA token (if exchanged via {@link #updateToken(Token)})
   * </ul>
   *
   * <p>To get the original token before any exchanges, use {@link #getInitialToken()}.
   *
   * @return the current access token, or {@code null} if none is set
   * @see #setToken(Token)
   * @see #updateToken(Token)
   */
  @Nullable
  public static Token getToken() {
    return get().token;
  }

  /**
   * Sets the access token for the current thread and resets the security context.
   *
   * <p>This method:
   *
   * <ol>
   *   <li>Sets {@code token} to the provided value
   *   <li>Saves a copy in {@code initialToken} (preserved even if {@code token} is later replaced)
   *   <li>Clears cached derived tokens ({@code idToken}, {@code xsuaaToken})
   * </ol>
   *
   * <p><b>Why Derived Tokens Are Cleared:</b> ID tokens and XSUAA tokens are derived from the
   * access token. When the access token changes, cached derived tokens become invalid and must be
   * re-resolved.
   *
   * <p><b>What Is NOT Cleared:</b>
   *
   * <ul>
   *   <li>Client certificate — Not token-specific, may persist across token rotations
   *   <li>Service plans — Part of the request context, not tied to the token
   *   <li>Extensions — Global configuration, not thread-specific
   * </ul>
   *
   * <p><b>Usage:</b>
   *
   * <pre>{@code
   * // In authentication filter
   * Token accessToken = parseAuthorizationHeader(request);
   * SecurityContext.setToken(accessToken);
   * }</pre>
   *
   * @param token the access token to set (typically from the HTTP Authorization header)
   */
  public static void setToken(Token token) {
    SecurityContext ctx = get();
    ctx.token = token;
    ctx.initialToken = token;
    ctx.idToken = null;
    ctx.xsuaaToken = null;
  }

  /**
   * Updates only the token field without clearing derived tokens or resetting context.
   *
   * <p><b>For internal usage only.</b> Use {@link #setToken(Token)} for normal authentication
   * scenarios. This method is intended for advanced scenarios like cross-thread token exchange
   * where you want to preserve other context properties.
   *
   * <p><b>Difference from {@link #setToken(Token)}:</b>
   *
   * <table>
   *   <caption>Method Comparison</caption>
   *   <tr>
   *     <th>Action</th>
   *     <th>{@code setToken(Token)}</th>
   *     <th>{@code updateToken(Token)}</th>
   *   </tr>
   *   <tr>
   *     <td>Updates {@code token}</td>
   *     <td>✅</td>
   *     <td>✅</td>
   *   </tr>
   *   <tr>
   *     <td>Updates {@code initialToken}</td>
   *     <td>✅</td>
   *     <td>❌</td>
   *   </tr>
   *   <tr>
   *     <td>Clears {@code idToken}</td>
   *     <td>✅</td>
   *     <td>❌</td>
   *   </tr>
   *   <tr>
   *     <td>Clears {@code xsuaaToken}</td>
   *     <td>✅</td>
   *     <td>❌</td>
   *   </tr>
   * </table>
   *
   * <p><b>Use Case: Cross-Thread Token Exchange</b>
   *
   * <pre>{@code
   * SecurityContext ctx = SecurityContext.get();
   * CompletableFuture.supplyAsync(() -> {
   *     Token exchangedToken = tokenExchange.exchange(ctx.token);
   *     ctx.updateToken(exchangedToken);  // Preserves idToken, extensions, etc.
   *     return callApi(exchangedToken);
   * });
   * }</pre>
   *
   * @param token the token to set
   */
  public void updateToken(Token token) {
    this.token = token;
  }

  /**
   * Returns the initial access token for the current thread.
   *
   * <p>This returns the original token set via {@link #setToken(Token)}, even if {@link #token} was
   * later replaced via {@link #updateToken(Token)}. Use this to access the original authentication
   * token after token exchanges.
   *
   * <p><b>Example: Hybrid IAS/XSUAA Scenario</b>
   *
   * <pre>{@code
   * // 1. IAS token from HTTP Authorization header
   * SecurityContext.setToken(iasToken);
   *
   * // 2. Exchange to XSUAA token
   * Token xsuaaToken = tokenExchange.exchange(iasToken);
   * SecurityContext.get().updateToken(xsuaaToken);
   *
   * // 3. Access tokens
   * Token current = SecurityContext.getToken();         // → xsuaaToken
   * Token original = SecurityContext.getInitialToken(); // → iasToken
   * }</pre>
   *
   * @return the initial access token, or {@code null} if none was set
   * @see #setToken(Token)
   */
  @Nullable
  public static Token getInitialToken() {
    return get().initialToken;
  }

  /**
   * Returns the current access token as an {@link AccessToken}, if applicable.
   *
   * <p>This is a convenience method that performs type checking and casting. It returns {@code
   * null} if the current token is not an {@link AccessToken} instance (e.g., if it's an ID token or
   * custom token implementation).
   *
   * <p><b>Usage:</b>
   *
   * <pre>{@code
   * AccessToken accessToken = SecurityContext.getAccessToken();
   * if (accessToken != null) {
   *     String clientId = accessToken.getClientId();
   *     List<String> scopes = accessToken.getScopes();
   * }
   * }</pre>
   *
   * @return the current token as {@link AccessToken}, or {@code null} if:
   *     <ul>
   *       <li>No token is set ({@link #getToken()} returns {@code null})
   *       <li>The token is not an instance of {@link AccessToken}
   *     </ul>
   */
  @Nullable
  public static AccessToken getAccessToken() {
    Token token = get().token;
    return token instanceof AccessToken ? (AccessToken) token : null;
  }

  /**
   * Removes the current access token from the security context.
   *
   * <p>This clears {@link #token} but does NOT clear:
   *
   * <ul>
   *   <li>{@link #initialToken}, {@link #idToken}, {@link #xsuaaToken} — Use {@link #clear()} to
   *       remove all tokens
   * </ul>
   *
   * <p>Subsequent calls to {@link #getToken()} will return {@code null} until a new token is set.
   */
  public static void clearToken() {
    SecurityContext ctx = get();
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
   * <p>This clears {@link #initialToken}
   */
  private static void clearInitialToken() {
    SecurityContext ctx = get();
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
   *   <li>Returns cached ID token if it exists and is valid
   *   <li>If {@link IdTokenExtension} is registered, calls {@link
   *       IdTokenExtension#resolveIdToken(Token)}
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
   *       <li>Token resolution fails (network error, invalid token, etc.)
   *       <li>No access token is available for token exchange
   *     </ul>
   *
   * @see IdTokenExtension#resolveIdToken(Token)
   * @see #registerIdTokenExtension(IdTokenExtension)
   */
  @Nullable
  public static Token getIdToken() {
    SecurityContext ctx = get();
    if (idTokenExtension != null) {
      ctx.idToken = idTokenExtension.resolveIdToken(ctx.idToken);
    }
    return ctx.idToken;
  }

  /**
   * Removes the cached ID token from the security context.
   *
   * <p>This forces re-resolution on the next {@link #getIdToken()} call if an {@link
   * IdTokenExtension} is registered.
   */
  private static void clearIdToken() {
    SecurityContext ctx = get();
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
   *   <li>Returns cached XSUAA token if it exists and is valid
   *   <li>If {@link XsuaaTokenExtension} is registered, calls {@link
   *       XsuaaTokenExtension#resolveXsuaaToken(Token)}
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
   * @see XsuaaTokenExtension#resolveXsuaaToken(Token)
   * @see #registerXsuaaTokenExtension(XsuaaTokenExtension)
   */
  @Nullable
  public static Token getXsuaaToken() {
    SecurityContext ctx = get();
    if (xsuaaTokenExtension != null) {
      ctx.xsuaaToken = xsuaaTokenExtension.resolveXsuaaToken(ctx.xsuaaToken);
    }
    return ctx.xsuaaToken;
  }

  /**
   * Removes the cached XSUAA token from the security context.
   *
   * <p>This forces re-resolution/exchange on the next {@link #getXsuaaToken()} call if a {@link
   * XsuaaTokenExtension} is registered.
   */
  private static void clearXsuaaToken() {
    SecurityContext ctx = get();
    if (ctx.xsuaaToken != null) {
      LOGGER.debug("XSUAA token removed from SecurityContext (thread-locally).");
      ctx.xsuaaToken = null;
    }
  }

  /**
   * Returns the X.509 client certificate for the current thread.
   *
   * <p>This is used in mutual TLS (mTLS) scenarios where the client authenticates via certificate
   * instead of (or in addition to) JWT tokens. The certificate is typically extracted from the HTTP
   * request by the web server/servlet container.
   *
   * <p><b>Usage: Certificate-Based Authentication</b>
   *
   * <pre>{@code
   * Certificate cert = SecurityContext.getClientCertificate();
   * if (cert != null) {
   *     String subjectDN = cert.getSubjectDN();
   *     // Perform certificate-based authorization
   * }
   * }</pre>
   *
   * @return the client certificate, or {@code null} if:
   *     <ul>
   *       <li>No certificate was set via {@link #setClientCertificate(Certificate)}
   *       <li>The current request does not use mTLS
   *     </ul>
   *
   * @see #setClientCertificate(Certificate)
   */
  @Nullable
  public static Certificate getClientCertificate() {
    return get().certificate;
  }

  /**
   * Sets the X.509 client certificate for the current thread's security context.
   *
   * <p>This is typically called by authentication filters/interceptors that extract the certificate
   * from the HTTP request. In servlet-based applications, the certificate is usually available via
   * the {@code javax.servlet.request.X509Certificate} request attribute.
   *
   * <p><b>Example: Servlet Filter</b>
   *
   * <pre>{@code
   * X509Certificate[] certs = (X509Certificate[])
   *     request.getAttribute("javax.servlet.request.X509Certificate");
   *
   * if (certs != null && certs.length > 0) {
   *     Certificate cert = Certificate.create(certs[0]);
   *     SecurityContext.setClientCertificate(cert);
   * }
   * }</pre>
   *
   * @param certificate the client certificate to store (may be {@code null} to clear it)
   * @see #getClientCertificate()
   */
  public static void setClientCertificate(Certificate certificate) {
    LOGGER.debug("Sets certificate to SecurityContext (thread-locally). {}", certificate);
    get().certificate = certificate;
  }

  /**
   * Removes the client certificate from the security context.
   *
   * <p>Subsequent calls to {@link #getClientCertificate()} will return {@code null} until a new
   * certificate is set.
   */
  private static void clearCertificate() {
    SecurityContext ctx = get();
    if (ctx.certificate != null) {
      LOGGER.debug("Certificate removed from SecurityContext (thread-locally).");
      ctx.certificate = null;
    }
  }

  /**
   * Returns the Identity Authentication Service plans associated with the current request.
   *
   * <p>Service plans indicate which IAS features/capabilities are available for the current
   * user/tenant. This information is typically extracted from custom HTTP headers (e.g., {@code
   * X-Identity-Service-Plan}) in multi-tenant scenarios.
   *
   * <p><b>Example Plans:</b>
   *
   * <ul>
   *   <li>{@code "default"} — Basic IAS features
   *   <li>{@code "application"} — Full IAS application features
   *   <li>{@code "sso"} — Single Sign-On enabled
   * </ul>
   *
   * @return the list of service plans, or {@code null} if:
   *     <ul>
   *       <li>No plans were set via {@link #setServicePlans(String)}
   *       <li>The current request does not include service plan information
   *     </ul>
   *
   * @see #setServicePlans(String)
   */
  @Nullable
  public static List<String> getServicePlans() {
    return get().servicePlans;
  }

  /**
   * Parses and stores Identity Authentication Service plans from a comma-separated header value.
   *
   * <p><b>Expected Format:</b> {@code "plan1", "plan2", "plan3"} <br>
   * Plans are extracted by splitting on commas and removing surrounding quotes.
   *
   * <p><b>Example:</b>
   *
   * <pre>{@code
   * // HTTP header: X-Identity-Service-Plan: "default", "application", "sso"
   * String header = request.getHeader("X-Identity-Service-Plan");
   * SecurityContext.setServicePlans(header);
   *
   * List<String> plans = SecurityContext.getServicePlans();
   * // → ["default", "application", "sso"]
   * }</pre>
   *
   * @param servicePlansHeader the comma-separated service plans header value (must not be {@code
   *     null})
   * @throws NullPointerException if {@code servicePlansHeader} is {@code null}
   * @see #getServicePlans()
   */
  public static void setServicePlans(String servicePlansHeader) {
    String[] planParts = servicePlansHeader.trim().split("\\s*,\\s*");

    List<String> plans =
        Arrays.stream(planParts)
            .map(plan -> plan.substring(1, plan.length() - 1)) // Remove quotes
            .collect(Collectors.toList());

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Sets Identity Service Plan {} to SecurityContext (thread-locally).", plans);
    }

    get().servicePlans = plans;
  }

  /**
   * Removes the service plans from the security context.
   *
   * <p>Subsequent calls to {@link #getServicePlans()} will return {@code null} until new plans are
   * set.
   */
  public static void clearServicePlans() {
    SecurityContext ctx = get();
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
   * <p>The extension is called by {@link #getIdToken()}. Only one extension can be registered at a
   * time; calling this method multiple times overwrites the previous extension.
   *
   * <p><b>Registration Timing:</b> Typically called once during application startup (e.g., in
   * Spring Boot's {@code @PostConstruct} or {@code ApplicationRunner}). However, per-request
   * registration is also supported for scenarios where dependency injection causes circular bean
   * initialization issues. Extensions are stateless, so overwriting the previous extension is safe.
   *
   * <p><b>Example: Spring Boot Configuration</b>
   *
   * <pre>{@code
   * @Configuration
   * public class SecurityConfig {
   *     @PostConstruct
   *     public void registerExtensions() {
   *         SecurityContext.registerIdTokenExtension(
   *             new DefaultIdTokenExtension(tokenService, iasConfig)
   *         );
   *     }
   * }
   * }</pre>
   *
   * @param ext the ID token extension to register (may be {@code null} to unregister)
   * @see IdTokenExtension#resolveIdToken(Token)
   * @see #getIdToken()
   */
  public static void registerIdTokenExtension(IdTokenExtension ext) {
    idTokenExtension = ext;
  }

  /**
   * Registers a global {@link XsuaaTokenExtension} for automatic XSUAA token resolution/exchange.
   *
   * <p>The extension is called by {@link #getXsuaaToken()}. Only one extension can be registered at
   * a time; calling this method multiple times overwrites the previous extension.
   *
   * <p><b>Registration Timing:</b> Typically called once during application startup (e.g., in
   * Spring Boot's {@code @PostConstruct} or {@code ApplicationRunner}). However, per-request
   * registration is also supported for scenarios where dependency injection causes circular bean
   * initialization issues. Extensions are stateless, so overwriting the previous extension is safe.
   *
   * <p><b>Example: Spring Boot Configuration</b>
   *
   * <pre>{@code
   * @Configuration
   * public class SecurityConfig {
   *     @PostConstruct
   *     public void registerExtensions() {
   *         SecurityContext.registerXsuaaTokenExtension(
   *             new DefaultXsuaaTokenExtension(tokenService, xsuaaConfig)
   *         );
   *     }
   * }
   * }</pre>
   *
   * @param ext the XSUAA token extension to register (may be {@code null} to unregister)
   * @see XsuaaTokenExtension#resolveXsuaaToken(Token)
   * @see #getXsuaaToken()
   */
  public static void registerXsuaaTokenExtension(XsuaaTokenExtension ext) {
    xsuaaTokenExtension = ext;
  }

  /**
   * Clears all security context data for the current thread.
   *
   * <p>This method removes:
   *
   * <ul>
   *   <li>Access token ({@link #token})
   *   <li>Initial token ({@link #initialToken})
   *   <li>Cached ID token ({@link #idToken})
   *   <li>Cached XSUAA token ({@link #xsuaaToken})
   *   <li>Client certificate ({@link #certificate})
   *   <li>Service plans ({@link #servicePlans})
   * </ul>
   *
   * <p><b>What Is NOT Cleared:</b>
   *
   * <ul>
   *   <li>Registered extensions ({@link #idTokenExtension}, {@link #xsuaaTokenExtension}) — These
   *       are global and shared across all threads
   *   <li>The {@code SecurityContext} instance itself — Kept in {@link ThreadLocal} for potential
   *       reuse
   * </ul>
   *
   * <p><b>Usage: Request Cleanup</b>
   *
   * <pre>{@code
   * try {
   *     SecurityContext.setToken(token);
   *     // ... process request ...
   * } finally {
   *     SecurityContext.clear();  // Clean up thread-local state
   * }
   * }</pre>
   *
   * <p><b>Difference from {@link #clearContext()}:</b>
   *
   * <ul>
   *   <li>{@code clear()} — Nulls out all fields but keeps the {@code SecurityContext} instance
   *   <li>{@code clearContext()} — Removes the entire {@code SecurityContext} from {@link
   *       ThreadLocal}
   * </ul>
   *
   * @see #clearContext()
   */
  public static void clear() {
    clearToken();
    clearInitialToken();
    clearIdToken();
    clearXsuaaToken();
    clearCertificate();
    clearServicePlans();
  }

  /**
   * Removes the entire {@code SecurityContext} instance from thread-local storage.
   *
   * <p>This performs complete {@link ThreadLocal} cleanup by removing the {@code SecurityContext}
   * instance. Use this to prevent memory leaks in thread pool environments where threads are reused
   * (e.g., servlet containers, application servers).
   *
   * <p><b>Difference from {@link #clear()}:</b>
   *
   * <ul>
   *   <li>{@code clear()} — Nulls out all fields but keeps the {@code SecurityContext} instance in
   *       {@link ThreadLocal} (faster for subsequent requests on the same thread)
   *   <li>{@code clearContext()} — Removes the entire instance from {@link ThreadLocal} (complete
   *       cleanup, prevents memory leaks)
   * </ul>
   *
   * <p><b>When to Use Each:</b>
   *
   * <table>
   *   <caption>Cleanup Method Comparison</caption>
   *   <tr>
   *     <th>Scenario</th>
   *     <th>Recommended Method</th>
   *   </tr>
   *   <tr>
   *     <td>Servlet request cleanup</td>
   *     <td>{@code clear()}</td>
   *   </tr>
   *   <tr>
   *     <td>Thread pool shutdown</td>
   *     <td>{@code clearContext()}</td>
   *   </tr>
   *   <tr>
   *     <td>Test cleanup (after each test)</td>
   *     <td>{@code clearContext()}</td>
   *   </tr>
   *   <tr>
   *     <td>Custom thread lifecycle management</td>
   *     <td>{@code clearContext()}</td>
   *   </tr>
   * </table>
   *
   * <p><b>Best Practice: Request Handling</b>
   *
   * <pre>{@code
   * try {
   *     SecurityContext.setToken(token);
   *     // ... process request ...
   * } finally {
   *     SecurityContext.clearContext();  // Complete cleanup
   * }
   * }</pre>
   *
   * @see #clear()
   */
  public static void clearContext() {
    contextStorage.remove();
    LOGGER.debug("Entire SecurityContext removed (thread-locally).");
  }
}