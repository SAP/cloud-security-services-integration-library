package com.sap.cloud.security.token;

import java.security.Principal;

import com.sap.cloud.security.config.Service;

public class TokenTestFactory {
	public static Token createFromJsonPayload(String jsonPayload) {
		return new AbstractToken(null, jsonPayload, null) {
			@Override
			public Principal getPrincipal() {
				return null;
			}

			@Override public Service getService() {
				return null;
			}
		};
	}
}
