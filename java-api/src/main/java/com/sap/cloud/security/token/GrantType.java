/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import javax.annotation.Nullable;

/**
 * Constants denoting the grant type of a Jwt access token as specified here:
 * <a href="https://tools.ietf.org/html/rfc6749"></a>
 */
public enum GrantType {
	// @formatter:off
	CLIENT_CREDENTIALS("client_credentials"),
	REFRESH_TOKEN("refresh_token"),
	PASSWORD("password"),
	JWT_BEARER("urn:ietf:params:oauth:grant-type:jwt-bearer"),
	SAML2_BEARER("urn:ietf:params:oauth:grant-type:saml2-bearer"),
	/**
	 * @deprecated in favor of {@link #JWT_BEARER}.
	 */
	@Deprecated
	USER_TOKEN("user_token"),
	/**
	 * @deprecated SAP proprietary grant type.
	 */
	@Deprecated
	CLIENT_X509("client_x509"),
	AUTHORIZATION_CODE("authorization_code");
	// @formatter:on
	private final String claimName;

	GrantType(String claimName) {
		this.claimName = claimName;
	}

	@Override
	public String toString() {
		return claimName;
	}

	@Nullable
	public static GrantType from(String claimName) {
		for (GrantType grantType : values()) {
			if (grantType.claimName.equals(claimName)) {
				return grantType;
			}
		}
		return null;
	}

}
