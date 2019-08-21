package com.sap.cloud.security.xsuaa.client;

import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

public class OAuth2AccessToken {
	private String refreshToken;
	private String accessToken;
	private long expiredTimeMillis;

	public OAuth2AccessToken(String accessToken, long expiredInSeconds, @Nullable String refreshToken) {
		Assert.hasText(accessToken, "accessToken is required");

		this.accessToken = accessToken;
		this.expiredTimeMillis = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiredInSeconds);
		this.refreshToken = refreshToken;
	}

	public String getValue() {
		return accessToken;
	}

	public Date getExpiredAtDate() {
		return new Date(expiredTimeMillis);
	}

	public Optional<String> getRefreshToken() {
		return Optional.ofNullable(refreshToken);
	}
}
