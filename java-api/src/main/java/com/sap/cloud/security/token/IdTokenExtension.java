package com.sap.cloud.security.token;

/**
 * Extension interface for resolving ID tokens in the {@link SecurityContext}.
 *
 * <p>Implementations of this interface can be registered with {@link
 * SecurityContext#registerIdTokenExtension(IdTokenExtension)} to enable automatic ID token
 * resolution when {@link SecurityContext#getIdToken()} is called and no valid cached token exists.
 *
 * <p>This is typically used to fetch ID tokens from an OAuth2 token service using the current
 * access token. The resolved token is automatically cached in the thread-local context for
 * subsequent calls.
 *
 * <p><b>Usage Example:</b>
 *
 * <pre>{@code
 * OAuth2ServiceConfiguration config = Environments.getCurrent().getIasConfiguration();
 * OAuth2TokenService tokenService = new XsuaaOAuth2TokenService();
 * DefaultIdTokenExtension extension = new DefaultIdTokenExtension(tokenService, config);
 * SecurityContext.registerIdTokenExtension(extension);
 * }</pre>
 *
 * @see SecurityContext#getIdToken()
 * @see SecurityContext#registerIdTokenExtension(IdTokenExtension)
 */
public interface IdTokenExtension {

  /**
   * Resolves an ID token for the current security context.
   *
   * <p>This method is called by {@link SecurityContext#getIdToken()} when:
   *
   * <ul>
   *   <li>No ID token is cached in the current thread's context
   *   <li>The cached ID token has expired (checked with 5-minute buffer)
   * </ul>
   *
   * <p>The resolved token is automatically cached in the {@link SecurityContext} for subsequent
   * calls within the same thread.
   *
   * @return the resolved ID token, or {@code null} if resolution fails or is not applicable
   */
  Token resolveIdToken();
}
