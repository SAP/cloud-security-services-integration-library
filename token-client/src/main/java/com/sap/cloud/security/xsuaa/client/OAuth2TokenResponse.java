/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nullable;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class OAuth2TokenResponse {
	static final String TOKEN_TYPE_DEFAULT = "bearer";
	private final String refreshToken;
	private final String accessToken;
	private final String tokenType;
	private final long expiredTimeMillis;

	public OAuth2TokenResponse(@Nullable String accessToken, long expiredInSeconds, @Nullable String refreshToken) {
		this(accessToken, expiredInSeconds, refreshToken, TOKEN_TYPE_DEFAULT);
	}

	public OAuth2TokenResponse(@Nullable String accessToken, long expiredInSeconds, @Nullable String refreshToken,
			String tokenType) {
		this.accessToken = accessToken;
		this.expiredTimeMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiredInSeconds);
		this.refreshToken = refreshToken;
		this.tokenType = tokenType;
	}

	/**
	 * An OAuth2 access token. This token will be a JSON Web Token suitable for
	 * offline validation by OAuth2 Resource Servers.
	 *
	 * @return the encoded access token
	 */
	@Nullable
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * A decoded OAuth2 access token.
	 *
	 * @return the decoded access token
	 */
	@Nullable
	public DecodedJwt getDecodedAccessToken() {
		if (accessToken == null) {
			return null;
		}
		return Base64JwtDecoder.getInstance().decode(accessToken);
	}

	/**
	 * Returns the moment in time when the token will be expired.
	 *
	 * @return the expiration point in time if present.
	 * @deprecated use {@link #getExpiredAt()}.
	 */
	@Deprecated
	public Date getExpiredAtDate() {
		return new Date(expiredTimeMillis);
	}

	/**
	 * Returns the moment in time when the token will be expired.
	 *
	 * @return the expiration point in time if present.
	 */
	public Instant getExpiredAt() {
		return Instant.ofEpochMilli(expiredTimeMillis);
	}

	/**
	 * An OAuth2 refresh token. Clients typically use the refresh token to obtain a
	 * new access token without the need for the user to authenticate again.
	 * 
	 * Note with version 2.5.0 the UserTokenFlow (Jwt Bearer) does not provide any
	 * longer Refresh Token.
	 *
	 * @return the refresh token - can only be used once!
	 */
	@Nullable
	public String getRefreshToken() {
		return refreshToken;
	}

	public String getTokenType() {
		return tokenType;
	}

	@Override
	public String toString() {
		DecodedJwt decodedJwt;
		try {
			decodedJwt = getDecodedAccessToken();
		} catch (IllegalArgumentException e) {
			return super.toString();
		}
		return decodedJwt.toString();
	}
}
