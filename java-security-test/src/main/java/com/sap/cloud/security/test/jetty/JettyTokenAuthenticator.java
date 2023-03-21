/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.jetty;

import com.sap.cloud.security.servlet.TokenAuthenticationResult;
import com.sap.cloud.security.servlet.TokenAuthenticator;
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Authentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

/**
 * Decorates the TokenAuthenticator and adapts it to Jetty.
 */
public class JettyTokenAuthenticator implements Authenticator {

	private static final Logger LOGGER = LoggerFactory.getLogger(JettyTokenAuthenticator.class);

	private final TokenAuthenticator tokenAuthenticator;

	public JettyTokenAuthenticator(TokenAuthenticator tokenAuthenticator) {
		this.tokenAuthenticator = tokenAuthenticator;
	}

	@Override
	public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory) {
		TokenAuthenticationResult tokenAuthenticationResult = tokenAuthenticator.validateRequest(request, response);
		if (tokenAuthenticationResult.isAuthenticated()) {
			return createAuthentication(tokenAuthenticationResult);
		} else {
			sendUnauthenticatedResponse(response, tokenAuthenticationResult.getUnauthenticatedReason());
			return Authentication.UNAUTHENTICATED;
		}
	}

	private void sendUnauthenticatedResponse(ServletResponse response, String unauthenticatedReason) {
		if (response instanceof HttpServletResponse) {
			try {
				HttpServletResponse httpServletResponse = (HttpServletResponse) response;
				httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, unauthenticatedReason); // 401
			} catch (IOException e) {
				LOGGER.error("Failed to send error response", e);
			}
		}
	}

	@Override
	public void setConfiguration(AuthConfiguration configuration) {
	}

	@Override
	public String getAuthMethod() {
		return "Token";
	}

	@Override
	public void prepareRequest(ServletRequest request) {
	}

	@Override
	public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory,
			Authentication.User validatedUser) {
		return true;
	}

	private Authentication createAuthentication(TokenAuthenticationResult tokenAuthentication) {
		Principal principal = tokenAuthentication.getPrincipal();
		Set<Principal> principals = new HashSet<>();
		principals.add(principal);
		Subject subject = new Subject(true, principals, new HashSet<>(), new HashSet<>());
		String[] scopes = tokenAuthentication.getScopes().toArray(new String[0]);
		return new UserAuthentication(getAuthMethod(), new DefaultUserIdentity(subject, principal, scopes));
	}
}
