package com.sap.cloud.security.token;

public class TokenTestFactory {
	public static Token createFromJsonPayload(String jsonPayload) {
		return new TokenImpl(null, jsonPayload, null);
	}
}
