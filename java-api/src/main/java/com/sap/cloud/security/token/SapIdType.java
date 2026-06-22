/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import jakarta.annotation.Nullable;

/**
 * Type of the principal an IAS-issued token belongs to. Mirrors the {@code sap_id_type} JWT claim
 * issued by SAP Cloud Identity Service.
 */
public enum SapIdType {
	/** Human end-user principal. */
	USER("user"),
	/** Technical / application principal. */
	APP("app");

	private final String claimValue;

	SapIdType(String claimValue) {
		this.claimValue = claimValue;
	}

	/**
	 * Returns the raw claim value used on the wire.
	 *
	 * @return the raw claim value as it appears in the JWT (e.g. {@code "user"} or {@code "app"}).
	 */
	public String claimValue() {
		return claimValue;
	}

	/**
	 * Resolves a {@link SapIdType} from a raw {@code sap_id_type} claim value.
	 *
	 * @param value the claim value, may be {@code null}
	 * @return the matching {@link SapIdType}, or {@code null} if {@code value} is {@code null} or
	 * 		does not match a known type (forward-compatibility for future values)
	 */
	@Nullable
	public static SapIdType fromClaimValue(@Nullable String value) {
		if (value == null) {
			return null;
		}
		for (SapIdType t : values()) {
			if (t.claimValue.equals(value)) {
				return t;
			}
		}
		return null;
	}
}