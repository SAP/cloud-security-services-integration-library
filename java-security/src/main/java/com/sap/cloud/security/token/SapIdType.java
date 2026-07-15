/**
 * SPDX-FileCopyrightText: 2018-2026 SAP SE or an SAP affiliate company and Cloud Security Client
 * Java contributors
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

/**
 * Known values of the {@code sap_id_type} claim emitted by the SAP Cloud Identity Service.
 *
 * <p>Kept as string constants — not an enum — so callers stay forward-compatible with future IAS
 * values that this library does not yet know about.
 */
public final class SapIdType {

  /** A human end user. */
  public static final String USER = "user";

  /** A technical / application principal (e.g. a service). */
  public static final String APP = "app";

  private SapIdType() {}
}
