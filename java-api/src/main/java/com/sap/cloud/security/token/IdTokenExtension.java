package com.sap.cloud.security.token;

/**
 * Extension interface for the {@link SecurityContext} to provide additional methods for extended
 * security contexts.
 */
public interface IdTokenExtension {

  /**
   * Resolves the ID token from the extended security context.
   *
   * @return the ID token or null if not available.
   */
  Token resolveIdToken();
}
