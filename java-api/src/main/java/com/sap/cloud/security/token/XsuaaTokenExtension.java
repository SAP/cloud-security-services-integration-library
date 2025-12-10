package com.sap.cloud.security.token;

import javax.annotation.Nullable;

/**
 * Extension interface for resolving and caching XSUAA tokens from IAS tokens.
 *
 * <p>This interface defines the contract for automatic XSUAA token exchange in hybrid
 * authentication scenarios (IAS Level 0 Migration). Implementations are responsible for:
 *
 * <ul>
 *   <li><b>Token Exchange:</b> Converting IAS tokens to XSUAA format via {@code /token_exchange}
 *       endpoint
 *   <li><b>Caching Logic:</b> Determining when to return cached tokens vs. re-exchanging
 *   <li><b>Expiration Handling:</b> Validating token expiration and triggering re-exchange when
 *       needed
 * </ul>
 *
 * <p><b>Hybrid Authentication Context:</b>
 *
 * <p>In hybrid scenarios, applications migrate from XSUAA-only to IAS-first authentication while
 * maintaining backward compatibility:
 *
 * <ol>
 *   <li><b>Incoming Token:</b> IAS token from HTTP Authorization header
 *   <li><b>Authorization Logic:</b> Still uses XSUAA scopes/roles (not yet migrated to IAS)
 *   <li><b>Token Exchange:</b> Extension converts IAS → XSUAA for authorization checks
 *   <li><b>Future Migration:</b> Eventually replace XSUAA authorization with IAS attributes
 * </ol>
 *
 * <p><b>Caching Strategy:</b>
 *
 * <p>The extension receives the currently cached XSUAA token (if any) and decides whether to:
 *
 * <ol>
 *   <li><b>Return cached token:</b> If it exists and is still valid
 *   <li><b>Re-exchange token:</b> If cached token is expired, missing, or otherwise invalid
 * </ol>
 *
 * This design decouples caching policy from {@link SecurityContext}, allowing implementations to
 * customize expiration checks, implement token refresh logic, or add custom validation rules.
 *
 * <p><b>Thread Safety:</b>
 *
 * <p>Implementations must be thread-safe as the extension is registered globally via {@link
 * SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)} but operates on thread-local
 * tokens. Multiple threads may call {@link #resolveXsuaaToken(Token)} concurrently.
 *
 * <p><b>Lifecycle:</b>
 *
 * <ol>
 *   <li><b>Registration:</b> Extension is registered once at application startup via {@link
 *       SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)}
 *   <li><b>Exchange:</b> Called by {@link SecurityContext#getXsuaaToken()} when XSUAA token is
 *       requested
 *   <li><b>Caching:</b> Returned token is cached in thread-local {@link SecurityContext}
 *   <li><b>Re-exchange:</b> Called again on next {@link SecurityContext#getXsuaaToken()} if cached
 *       token expired
 * </ol>
 *
 * <p><b>Configuration Requirements:</b>
 *
 * <p>XSUAA token exchange requires proper Cloud Foundry service binding configuration:
 *
 * <pre>{@code
 * # manifest.yml
 * services:
 *   - xsuaa-service
 * env:
 *   xsuaa-cross-consumption: true  # Enable IAS-to-XSUAA exchange
 * }</pre>
 *
 * <p><b>Usage Example (Spring Boot):</b>
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
 * <p><b>Error Handling:</b>
 *
 * <p>Implementations should handle errors gracefully and return {@code null} if exchange fails
 * (network errors, invalid configuration, missing XSUAA binding, etc.). {@link SecurityContext}
 * will propagate the {@code null} to callers, allowing them to handle missing XSUAA tokens
 * appropriately.
 *
 * @see SecurityContext#getXsuaaToken()
 * @see SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)
 * @see SecurityContext#clearXsuaaToken()
 */
public interface XsuaaTokenExtension {

  /**
   * Resolves a XSUAA token from the current security context (typically via IAS-to-XSUAA exchange).
   *
   * <p>This method is called by {@link SecurityContext#getXsuaaToken()} to lazily exchange IAS
   * tokens to XSUAA format when needed. The implementation receives the currently cached XSUAA
   * token (if any) and decides whether to return it or exchange a new one.
   *
   * <p><b>Caching Responsibility:</b>
   *
   * <p>The implementation is responsible for:
   *
   * <ol>
   *   <li><b>Checking cached token validity:</b> Inspect {@code cachedXsuaaToken} expiration
   *   <li><b>Deciding whether to re-exchange:</b> Return cached token if valid, otherwise exchange
   *       new token
   *   <li><b>Token exchange:</b> If re-exchange needed, convert IAS token to XSUAA format
   * </ol>
   *
   * <p><b>Source Token Availability:</b>
   *
   * <p>The source token (typically IAS) is available via {@link SecurityContext#getToken()}. If no
   * token exists or it's already a XSUAA token, the implementation should return {@code null} or
   * the existing Token since exchange is unnecessary.
   *
   * <p><b>Return Value Handling:</b>
   *
   * <ul>
   *   <li><b>Non-null token:</b> Cached in {@link SecurityContext} for subsequent {@link
   *       SecurityContext#getXsuaaToken()} calls
   *   <li><b>{@code null}:</b> No caching occurs; subsequent calls will re-invoke this method
   * </ul>
   *
   * <p><b>Thread Safety:</b>
   *
   * <p>This method may be called concurrently from multiple threads. Implementations must be
   * stateless or use proper synchronization.
   *
   * @param cachedXsuaaToken the currently cached XSUAA token from thread-local {@link
   *     SecurityContext}, or {@code null} if:
   *     <ul>
   *       <li>No XSUAA token has been exchanged yet for this thread
   *       <li>The cached token was cleared via {@link SecurityContext#clearXsuaaToken()}
   *       <li>The security context was reset via {@link SecurityContext#setToken(Token)}
   *     </ul>
   *
   * @return the resolved XSUAA token (may be the cached token if still valid), or {@code null} if:
   *     <ul>
   *       <li>No IAS token is available in the security context
   *       <li>Token exchange fails (network error, invalid configuration, missing XSUAA binding,
   *           etc.)
   *     </ul>
   */
  Token resolveXsuaaToken(@Nullable Token cachedXsuaaToken);
}
