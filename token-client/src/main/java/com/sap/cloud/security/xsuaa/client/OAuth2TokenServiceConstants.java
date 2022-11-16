/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

public class OAuth2TokenServiceConstants {

	private OAuth2TokenServiceConstants() {
		throw new IllegalStateException("Utility class");
	}

	public static final String ACCESS_TOKEN = "access_token";
	public static final String EXPIRES_IN = "expires_in";
	public static final String REFRESH_TOKEN = "refresh_token";
	public static final String TOKEN_TYPE = "token_type";
	public static final String CLIENT_ID = "client_id";
	public static final String CLIENT_SECRET = "client_secret";
	public static final String USERNAME = "username";
	public static final String PASSWORD = "password"; // NOSONAR
	public static final String ASSERTION = "assertion";
	public static final String AUTHORITIES = "authorities";
	public static final String SCOPE = "scope";

	public static final String GRANT_TYPE = "grant_type";
	/**
	 * @deprecated in favor of {@link #GRANT_TYPE_JWT_BEARER}.
	 */
	@Deprecated
	public static final String GRANT_TYPE_USER_TOKEN = "user_token";
	public static final String GRANT_TYPE_REFRESH_TOKEN = "refresh_token";
	public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";
	public static final String GRANT_TYPE_PASSWORD = "password"; // NOSONAR
	public static final String GRANT_TYPE_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
	/**
	 * @deprecated SAP proprietary grant type.
	 */
	@Deprecated
	public static final String GRANT_TYPE_CLIENT_X509 = "client_x509";
	public static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"; // not supported by token-client
																						// lib

	public static final String TOKEN_TYPE_OPAQUE = "opaque";

	public static final String PARAMETER_CLIENT_ID = "client_id";
}
