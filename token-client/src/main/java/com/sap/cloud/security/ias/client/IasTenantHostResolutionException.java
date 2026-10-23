/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import java.io.IOException;
import java.io.Serial;

import jakarta.annotation.Nonnull;

/**
 * Exception thrown when the subscriber IAS tenant host cannot be resolved via the BTP tenant API.
 * <p>
 * Carries a machine-readable {@link ErrorCode} so callers can decide on a reaction strategy:
 * <ul>
 *   <li>{@link ErrorCode#UPSTREAM_UNAVAILABLE} — transient. The IAS registry or the network was
 *       unreachable (HTTP 424/5xx or a transport error). A retry after a short delay may succeed.</li>
 *   <li>{@link ErrorCode#INVALID_REQUEST}, {@link ErrorCode#AUTHENTICATION_FAILED},
 *       {@link ErrorCode#TENANT_NOT_FOUND}, {@link ErrorCode#UPSTREAM_MISCONFIGURED},
 *       {@link ErrorCode#TENANT_INACTIVE}, {@link ErrorCode#NOT_TRUSTED} and
 *       {@link ErrorCode#TENANT_INFO_ERROR} — stable. A retry with the same input is not expected
 *       to succeed until the underlying condition changes (e.g. the trust between the provider and
 *       subscriber tenant is established, or the service key is fixed).</li>
 * </ul>
 * <p>
 * Error codes are derived from the BTP tenant API contract of
 * {@code GET /sap/rest/tenantLoginInfo}:
 * <ul>
 *   <li>HTTP 400 — {@code id} and {@code subdomain} are not mutually exclusive or both missing →
 *       {@link ErrorCode#INVALID_REQUEST}</li>
 *   <li>HTTP 401/403 — the service credentials of this application are rejected →
 *       {@link ErrorCode#AUTHENTICATION_FAILED}</li>
 *   <li>HTTP 404 — the tenant is unknown to the BTP tenant API → {@link ErrorCode#TENANT_NOT_FOUND}</li>
 *   <li>HTTP 424 — the IAS registry returned an error or is temporarily unreachable →
 *       {@link ErrorCode#UPSTREAM_UNAVAILABLE}</li>
 *   <li>HTTP 500 — the IAS registry URL is misconfigured or its certificate is invalid →
 *       {@link ErrorCode#UPSTREAM_MISCONFIGURED}</li>
 *   <li>HTTP 5xx (other) — transient upstream failure → {@link ErrorCode#UPSTREAM_UNAVAILABLE}</li>
 *   <li>HTTP 200 with response {@code status} {@code INACTIVE} / {@code NOTRUST} / {@code ERROR} →
 *       {@link ErrorCode#TENANT_INACTIVE} / {@link ErrorCode#NOT_TRUSTED} /
 *       {@link ErrorCode#TENANT_INFO_ERROR} (the API's {@code error_details} are propagated into the
 *       message)</li>
 *   <li>HTTP 200 with a missing/unknown {@code status} or a malformed response →
 *       {@link ErrorCode#TENANT_INFO_ERROR}</li>
 *   <li>Transport error (timeout, connection refused, ...) → {@link ErrorCode#UPSTREAM_UNAVAILABLE}</li>
 * </ul>
 */
public class IasTenantHostResolutionException extends IOException {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Machine-readable reason of a failed tenant host resolution.
   */
  public enum ErrorCode {
    /**
     * The request was rejected by the BTP tenant API as malformed (HTTP 400), or the supplied
     * tenant ID did not pass the library's local format validation.
     */
    INVALID_REQUEST,
    /** The service credentials presented to the BTP tenant API were rejected (HTTP 401/403). */
    AUTHENTICATION_FAILED,
    /** The tenant ID is unknown to the BTP tenant API (HTTP 404). */
    TENANT_NOT_FOUND,
    /**
     * The upstream IAS registry is temporarily unavailable (HTTP 424, other 5xx, transport error).
     * This error is transient and a retry may succeed.
     */
    UPSTREAM_UNAVAILABLE,
    /** The upstream IAS registry is misconfigured (HTTP 500). A retry is not expected to help. */
    UPSTREAM_MISCONFIGURED,
    /** The tenant exists but is currently inactive (API status {@code INACTIVE}). */
    TENANT_INACTIVE,
    /** No trust relationship between the provider and the subscriber tenant is established (API status {@code NOTRUST}). */
    NOT_TRUSTED,
    /**
     * The API answered with status {@code ERROR} (the {@code error_details} value is part of the
     * message), the {@code status} field was missing/unknown, or the response could not be parsed.
     */
    TENANT_INFO_ERROR
  }

  private final ErrorCode errorCode;
  private final Integer httpStatusCode;

  /**
   * Creates a new exception with a local (non-HTTP) error code.
   *
   * @param errorCode the error code, must not be null
   * @param message the human-readable message
   * @param cause the underlying cause, may be {@code null}
   */
  public IasTenantHostResolutionException(@Nonnull ErrorCode errorCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
    this.httpStatusCode = 0;
  }

  /**
   * Creates a new exception with an HTTP error code.
   *
   * @param errorCode the error code, must not be null
   * @param httpStatusCode the HTTP status code returned by the BTP tenant API
   * @param message the human-readable message
   * @param cause the underlying cause, may be {@code null}
   */
  public IasTenantHostResolutionException(
      @Nonnull ErrorCode errorCode, int httpStatusCode, String message, Throwable cause) {
    super(message, cause);
    this.errorCode = errorCode;
    this.httpStatusCode = httpStatusCode;
  }

  /**
   * @return the machine-readable error code
   */
  @Nonnull
  public ErrorCode getErrorCode() {
    return errorCode;
  }

  /**
   * @return the HTTP status code returned by the BTP tenant API, or {@code 0} if the error is
   *     local (e.g. input validation) and no HTTP status applies
   */
  public int getHttpStatusCode() {
    return httpStatusCode;
  }
}
