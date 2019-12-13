package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

public interface TokenAuthenticator {

	TokenAuthenticationResult validateRequest(ServletRequest request, ServletResponse response);

	TokenExtractor getTokenExtractor();

	interface TokenExtractor {
		Token from(String authorizationHeader);
	}
}
