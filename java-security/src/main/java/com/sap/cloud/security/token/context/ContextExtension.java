package com.sap.cloud.security.token.context;

public interface ContextExtension {

  /**
   * Applies the extension logic, e.g. modifies the {@link
   * com.sap.cloud.security.token.SecurityContext}.
   *
   * @throws Exception in case of errors
   */
  void extend() throws Exception;
}
