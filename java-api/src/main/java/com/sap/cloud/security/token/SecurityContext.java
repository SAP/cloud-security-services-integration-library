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
 * Thread wide {@link Token} storage.
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
   */
  private static class ContextHolder {
    Token token;
    Token idToken;
    Token xsuaaToken;
    Token initialToken;
    Certificate certificate;
    List<String> servicePlans;

    // Helper to check token validity
    boolean isTokenValid(Token token) {
      return token != null
          && token.getExpiration() != null
          && token.getExpiration().minus(5, ChronoUnit.MINUTES).isAfter(Instant.now());
    }
  }

  private static ContextHolder getContext() {
    return contextStorage.get();
  }

  public static void setToken(Token token) {
    LOGGER.debug(
        "Sets token of service {} to SecurityContext (thread-locally).",
        token != null ? token.getService() : "null");
    ContextHolder ctx = getContext();
    ctx.token = token;
    ctx.initialToken = token;
    ctx.idToken = null; // Clear cached ID token
  }

  public static void overwriteToken(Token token) {
    LOGGER.debug(
        "Overwrites token of service {} in SecurityContext (thread-locally).",
        token != null ? token.getService() : "null");
    getContext().token = token;
  }

  @Nullable
  public static Token getToken() {
    return getContext().token;
  }

  @Nullable
  public static Token getInitialToken() {
    return getContext().initialToken;
  }

  @Nullable
  public static AccessToken getAccessToken() {
    Token token = getContext().token;
    return token instanceof AccessToken ? (AccessToken) token : null;
  }

  public static void clearToken() {
    ContextHolder ctx = getContext();
    if (ctx.token != null) {
      LOGGER.debug(
          "Token of service {} removed from SecurityContext (thread-locally).",
          ctx.token.getService());
      ctx.token = null;
    }
  }

  public static void clearInitialToken() {
    ContextHolder ctx = getContext();
    if (ctx.initialToken != null) {
      LOGGER.debug(
          "Initial token of service {} removed from SecurityContext (thread-locally).",
          ctx.initialToken.getService());
      ctx.initialToken = null;
    }
  }

  /*
   * Retrieves the ID token associated with the current context.
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

  public static void clearIdToken() {
    ContextHolder ctx = getContext();
    if (ctx.idToken != null) {
      LOGGER.debug("ID token removed from SecurityContext (thread-locally).");
      ctx.idToken = null;
    }
  }

  /*
   * Retrieves the XSUAA token associated with the current context.
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

  public static void clearXsuaaToken() {
    ContextHolder ctx = getContext();
    if (ctx.xsuaaToken != null) {
      LOGGER.debug("XSUAA token removed from SecurityContext (thread-locally).");
      ctx.xsuaaToken = null;
    }
  }

  @Nullable
  public static Certificate getClientCertificate() {
    return getContext().certificate;
  }

  public static void setClientCertificate(Certificate certificate) {
    LOGGER.debug("Sets certificate to SecurityContext (thread-locally). {}", certificate);
    getContext().certificate = certificate;
  }

  private static void clearCertificate() {
    ContextHolder ctx = getContext();
    if (ctx.certificate != null) {
      LOGGER.debug("Certificate removed from SecurityContext (thread-locally).");
      ctx.certificate = null;
    }
  }

  @Nullable
  public static List<String> getServicePlans() {
    return getContext().servicePlans;
  }

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

  public static void registerIdTokenExtension(IdTokenExtension ext) {
    idTokenExtension = ext;
  }

  public static void registerXsuaaTokenExtension(XsuaaTokenExtension ext) {
    xsuaaTokenExtension = ext;
  }

  /** Clears all stored data for the current thread. */
  public static void clear() {
    clearCertificate();
    clearToken();
    clearIdToken();
    clearXsuaaToken();
    clearInitialToken();
    clearServicePlans();
  }

  /**
   * Removes the entire context for the current thread. Use this to clean up ThreadLocal storage
   * completely.
   */
  public static void clearContext() {
    contextStorage.remove();
    LOGGER.debug("Entire SecurityContext removed (thread-locally).");
  }
}