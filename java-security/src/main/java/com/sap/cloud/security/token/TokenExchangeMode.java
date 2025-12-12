package com.sap.cloud.security.token;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Defines token exchange modes for hybrid authentication scenarios.
 *
 * <p>Controls how hybrid authentication components handle IAS-to-XSUAA token exchange during
 * request processing. This is relevant for Level 0 migration where applications receive IAS tokens
 * but still use XSUAA-based authorization.
 *
 * @see SecurityContext#getXsuaaToken()
 */
public enum TokenExchangeMode {

  /**
   * Token exchange is disabled.
   *
   * <p>Tokens are validated but not exchanged. Use this mode when:
   *
   * <ul>
   *   <li>Application only accepts XSUAA tokens (no IAS support)
   *   <li>Application uses IAS authorization (no XSUAA exchange needed)
   *   <li>Testing/debugging without token exchange overhead
   * </ul>
   */
  DISABLED,

  /**
   * Provides XSUAA token alongside the original token.
   *
   * <p>Both IAS and XSUAA tokens are available after validation:
   *
   * <ul>
   *   <li><b>Original token:</b> {@link SecurityContext#getToken()} returns IAS/XSUAA token
   *   <li><b>Exchanged token:</b> {@link SecurityContext#getXsuaaToken()} returns XSUAA token
   * </ul>
   *
   * Use this mode when authorization logic needs XSUAA scopes but you want to preserve the original
   * IAS token for auditing/logging.
   */
  PROVIDE_XSUAA,

  /**
   * Forces XSUAA token as the primary token.
   *
   * <p>If an IAS token is received, it's exchanged to XSUAA format and replaces the original token:
   *
   * <ul>
   *   <li><b>IAS token input:</b> {@link SecurityContext#getToken()} returns exchanged XSUAA token
   *   <li><b>XSUAA token input:</b> {@link SecurityContext#getToken()} returns original XSUAA token
   * </ul>
   *
   * Use this mode when authorization logic exclusively uses XSUAA scopes and you want a unified
   * token type regardless of input format.
   */
  FORCE_XSUAA;

  /**
   * Parses a string value into a {@link TokenExchangeMode}.
   *
   * <p>Supports case-insensitive parsing:
   *
   * <ul>
   *   <li>{@code "disabled"} → {@link #DISABLED}
   *   <li>{@code "provideXsuaa"} → {@link #PROVIDE_XSUAA}
   *   <li>{@code "forceXsuaa"} → {@link #FORCE_XSUAA}
   * </ul>
   *
   * @param value the string value to parse (case-insensitive, null/empty returns DISABLED)
   * @return the corresponding enum constant
   * @throws IllegalArgumentException if the value doesn't match any mode
   */
  public static TokenExchangeMode fromString(String value) {
    final Logger logger = LoggerFactory.getLogger(TokenExchangeMode.class);
    if (value == null || value.isEmpty()) {
      return DISABLED;
    }
    return switch (value.toLowerCase()) {
      case "disabled" -> DISABLED;
      case "providexsuaa" -> PROVIDE_XSUAA;
      case "forcexsuaa" -> FORCE_XSUAA;
      default -> {
        logger.error("Wrong Token exchange mode: {}. Disabling Token Exchange...", value);
        yield DISABLED;
      }
    };
  }
}
