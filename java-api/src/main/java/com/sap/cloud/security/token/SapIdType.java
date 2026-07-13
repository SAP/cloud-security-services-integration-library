/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

/**
 * Known values of the {@code sap_id_type} JWT claim issued by SAP Cloud Identity Service.
 *
 * <p>Exposed as string constants rather than an enum so that consumers remain forward-compatible
 * with values introduced by future IAS versions: {@link SapIdToken#getIdType()} returns the raw
 * claim string, and callers can compare against the constants defined here for the values known
 * today.
 */
public final class SapIdType {

	/** Human end-user principal. */
	public static final String USER = "user";

	/** Technical / application principal. */
	public static final String APP = "app";

	private SapIdType() {
	}
}