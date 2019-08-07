package com.sap.cloud.security.xsuaa.backend;

import java.util.Date;
import java.util.Optional;

public class OAuth2AccessToken {
	protected String refreshToken;
	protected String accessToken;
	protected long expiredInSeconds;

	public OAuth2AccessToken(String accessToken, long expiredInSeconds) {
		this.accessToken = accessToken;
		this.expiredInSeconds = expiredInSeconds;
	}

	public OAuth2AccessToken(String accessToken, String refreshToken, long expiredInSeconds) {
		this(accessToken, expiredInSeconds);
		this.refreshToken = refreshToken;
	}

	public String getValue() {
		return accessToken;
	}

	public Date getExpiredAtDate() {
		return calculateDate(expiredInSeconds);
	}

	private Date calculateDate(long expiredInSeconds) {
		long timeInMilliSeconds = getCurrentTime().getTime();
		timeInMilliSeconds += expiredInSeconds * 1000;
		return new Date(timeInMilliSeconds);
	}

	//for testing only
	Date getCurrentTime() {
		return new Date();
	}

	public Optional<String> getRefreshToken() {
		return Optional.of(refreshToken);
	}
}
