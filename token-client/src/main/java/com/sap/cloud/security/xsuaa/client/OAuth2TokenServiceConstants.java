/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

public class OAuth2TokenServiceConstants {

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
    public static final long RETRY_MAX_DELAY_TIME = 10000L;
    public static final String GRANT_TYPE = "grant_type";
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
    public static final String TOKEN_FORMAT = "token_format";
    public static final String TOKEN_TYPE_OPAQUE = "opaque";
    public static final String PARAMETER_CLIENT_ID = "client_id";

    private OAuth2TokenServiceConstants() {
        throw new IllegalStateException("Utility class");
    }
}
