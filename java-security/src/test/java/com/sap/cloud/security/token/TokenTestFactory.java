package com.sap.cloud.security.token;

import java.security.Principal;

public class TokenTestFactory {
	public static Token createFromJsonPayload(String jsonPayload) {
		return new AbstractToken(null, jsonPayload, null) {
			@Override
			public Principal getPrincipal() {
				return null;
			}
		};
	}
}
