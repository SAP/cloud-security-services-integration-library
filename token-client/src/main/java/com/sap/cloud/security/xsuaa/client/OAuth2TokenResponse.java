package com.sap.cloud.security.xsuaa.client;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.lang.Nullable;

public class OAuth2TokenResponse {
	private String refreshToken;
	private String accessToken;
	private long expiredTimeMillis;

	public OAuth2TokenResponse(@Nullable String accessToken, long expiredInSeconds, @Nullable String refreshToken) {
		this.accessToken = accessToken;
		this.expiredTimeMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiredInSeconds);
		this.refreshToken = refreshToken;
	}

	/**
	 * An OAuth2 access token. This token will be a JSON Web Token suitable for
	 * offline validation by OAuth2 Resource Servers.
	 *
	 * @return the access token
	 */
	@Nullable
	public String getAccessToken() {
		return accessToken;
	}

	public Date getExpiredAtDate() {
		return new Date(expiredTimeMillis);
	}

	/**
	 * An OAuth2 refresh token. Clients typically use the refresh token to obtain a
	 * new access token without the need for the user to authenticate again.
	 *
	 * @return the refresh token - can only be used once!
	 */
	@Nullable
	public String getRefreshToken() {
		return refreshToken;
	}

	@Override
	public String toString() {
		return getAccessToken() != null ? getAccessToken() : super.toString();
	}
}
