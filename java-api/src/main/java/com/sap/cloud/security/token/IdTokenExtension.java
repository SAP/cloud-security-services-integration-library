package com.sap.cloud.security.token;

import javax.annotation.Nullable;

/**
 * Extension interface for resolving and caching ID tokens from access tokens.
 *
 * <p>This interface defines the contract for automatic ID token resolution in {@link
 * SecurityContext}. Implementations are responsible for:
 *
 * <ul>
 *   <li><b>Token Exchange:</b> Converting access tokens to ID tokens (e.g., via OAuth2 token
 *       exchange)
 *   <li><b>Caching Logic:</b> Determining when to return cached tokens vs. re-resolving
 *   <li><b>Expiration Handling:</b> Validating token expiration and triggering re-resolution when
 *       needed
 * </ul>
 *
 * <p><b>Caching Strategy:</b>
 *
 * <p>The extension receives the currently cached ID token (if any) and decides whether to:
 *
 * <ol>
 *   <li><b>Return cached token:</b> If it exists and is still valid
 *   <li><b>Re-resolve token:</b> If cached token is expired, missing, or otherwise invalid
 * </ol>
 *
 * This design decouples caching policy from {@link SecurityContext}, allowing implementations to
 * customize expiration checks, implement token refresh logic, or add custom validation rules.
 *
 * <p><b>Thread Safety:</b>
 *
 * <p>Implementations must be thread-safe as the extension is registered globally via {@link
 * SecurityContext#registerIdTokenExtension(IdTokenExtension)} but operates on thread-local tokens.
 * Multiple threads may call {@link #resolveIdToken(Token)} concurrently.
 *
 * <p><b>Lifecycle:</b>
 *
 * <ol>
 *   <li><b>Registration:</b> Extension is registered once at application startup via {@link
 *       SecurityContext#registerIdTokenExtension(IdTokenExtension)}
 *   <li><b>Resolution:</b> Called by {@link SecurityContext#getIdToken()} when ID token is
 *       requested
 *   <li><b>Caching:</b> Returned token is cached in thread-local {@link SecurityContext}
 *   <li><b>Re-resolution:</b> Called again on next {@link SecurityContext#getIdToken()} if cached
 *       token expired
 * </ol>
 *
 * <p><b>Usage Example (Spring Boot):</b>
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
 * <p><b>Error Handling:</b>
 *
 * <p>Implementations should handle errors gracefully and return {@code null} if resolution fails
 * (network errors, invalid tokens, missing configuration, etc.). {@link SecurityContext} will
 * propagate the {@code null} to callers, allowing them to handle missing ID tokens appropriately.
 *
 * @see SecurityContext#getIdToken()
 * @see SecurityContext#registerIdTokenExtension(IdTokenExtension)
 * @see SecurityContext#clearIdToken()
 */
public interface IdTokenExtension {

  /**
   * Resolves an ID token from the current security context.
   *
   * <p>This method is called by {@link SecurityContext#getIdToken()} to lazily resolve ID tokens
   * when needed. The implementation receives the currently cached ID token (if any) and decides
   * whether to return it or resolve a new one.
   *
   * <p><b>Caching Responsibility:</b>
   *
   * <p>The implementation is responsible for:
   *
   * <ol>
   *   <li><b>Checking cached token validity:</b> Inspect {@code cachedIdToken} expiration
   *   <li><b>Deciding whether to re-resolve:</b> Return cached token if valid, otherwise resolve
   *       new token
   *   <li><b>Token exchange:</b> If re-resolution needed, exchange access token for ID token
   * </ol>
   *
   * <p><b>Access Token Availability:</b>
   *
   * <p>The access token is available via {@link SecurityContext#getToken()}. If no access token
   * exists, the implementation should return {@code null} since token exchange is impossible.
   *
   * <p><b>Return Value Handling:</b>
   *
   * <ul>
   *   <li><b>Non-null token:</b> Cached in {@link SecurityContext} for subsequent {@link
   *       SecurityContext#getIdToken()} calls
   *   <li><b>{@code null}:</b> No caching occurs; subsequent calls will re-invoke this method
   * </ul>
   *
   * <p><b>Thread Safety:</b>
   *
   * <p>This method may be called concurrently from multiple threads. Implementations must be
   * stateless or use proper synchronization.
   *
   * @param cachedIdToken the currently cached ID token from thread-local {@link SecurityContext},
   *     or {@code null} if:
   *     <ul>
   *       <li>No ID token has been resolved yet for this thread
   *       <li>The cached token was cleared via {@link SecurityContext#clearIdToken()}
   *       <li>The security context was reset via {@link SecurityContext#setToken(Token)}
   *     </ul>
   *
   * @return the resolved ID token (may be the cached token if still valid), or {@code null} if:
   *     <ul>
   *       <li>No access token is available in the security context
   *       <li>Token exchange fails (network error, invalid configuration, etc.)
   *       <li>The access token does not support ID token exchange
   *     </ul>
   */
  Token resolveIdToken(@Nullable Token cachedIdToken);
}
