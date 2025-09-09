package com.sap.cloud.security.token.context;

import java.util.ArrayList;
import java.util.List;

/** Registry for all registered {@link ContextExtension} implementations. */
public class ContextExtensionsRegistry {
  private static final List<ContextExtension> extensions = new ArrayList<>();

  /**
   * Registers a new {@link ContextExtension} implementation.
   *
   * @param ext the extension to register
   */
  public static void add(final ContextExtension ext) {
    extensions.add(ext);
  }

  /**
   * Applies all registered {@link ContextExtension} implementations in the order they were
   * registered.
   *
   * @throws Exception in case of errors
   */
  public void applyAll() throws Exception {
    for (final ContextExtension ext : extensions) {
      ext.extend();
    }
  }
}
