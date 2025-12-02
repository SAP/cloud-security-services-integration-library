package com.sap.cloud.security.token;

/**
 * Extension interface for resolving XSUAA tokens in the {@link SecurityContext}.
 *
 * <p>Implementations of this interface can be registered with {@link
 * SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)} to enable automatic XSUAA token
 * resolution when {@link SecurityContext#getXsuaaToken()} is called and no valid cached token
 * exists.
 *
 * <p>This is primarily used in <b>hybrid authentication scenarios</b> where an application receives
 * Identity Authentication Service (IAS) tokens but needs XSUAA tokens to maintain compatibility
 * with existing XSUAA-based authorization logic. The extension performs automatic token exchange
 * from IAS to XSUAA format.
 *
 * <p><b>Prerequisites:</b> Token exchange requires the following Cloud Foundry manifest
 * configuration:
 *
 * <pre>{@code
 * services:
 *   - name: xsuaa-authn
 *   - name: ias-authn
 *     parameters:
 *       xsuaa-cross-consumption: true  # Enable token exchange
 * }</pre>
 *
 * <p><b>Usage Example:</b>
 *
 * <pre>{@code
 * OAuth2ServiceConfiguration xsuaaConfig = Environments.getCurrent().getXsuaaConfiguration();
 * OAuth2TokenService tokenService = new XsuaaOAuth2TokenService();
 * DefaultXsuaaTokenExtension extension = new DefaultXsuaaTokenExtension(tokenService, xsuaaConfig);
 * SecurityContext.registerXsuaaTokenExtension(extension);
 * }</pre>
 *
 * @see SecurityContext#getXsuaaToken()
 * @see SecurityContext#registerXsuaaTokenExtension(XsuaaTokenExtension)
 */
public interface XsuaaTokenExtension {

  /**
   * Resolves a XSUAA token for the current security context.
   *
   * <p>This method is called by {@link SecurityContext#getXsuaaToken()} when:
   *
   * <ul>
   *   <li>No XSUAA token is cached in the current thread's context
   *   <li>The cached XSUAA token has expired (checked with 5-minute expiration buffer)
   * </ul>
   *
   * <p>Implementations typically:
   *
   * <ol>
   *   <li>Check if the current token from {@link SecurityContext#getToken()} is already a XSUAA
   *       token
   *   <li>If yes, return it immediately without exchange
   *   <li>If it's an IAS token, exchange it to XSUAA format using JWT Bearer grant
   *   <li>Cache the exchanged token via {@link SecurityContext#overwriteToken(Token)}
   * </ol>
   *
   * <p>The resolved token is automatically cached in the {@link SecurityContext} for subsequent
   * calls within the same thread. Implementations should handle errors gracefully and return {@code
   * null} on failure.
   *
   * @return the resolved XSUAA token (existing or exchanged), or {@code null} if resolution fails
   *     or no token is available
   */
  Token resolveXsuaaToken();
}
