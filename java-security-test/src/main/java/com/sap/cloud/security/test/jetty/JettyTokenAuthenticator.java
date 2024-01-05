/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.test.jetty;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import javax.security.auth.Subject;

import org.eclipse.jetty.ee10.servlet.ServletContextRequest;
import org.eclipse.jetty.ee10.servlet.ServletContextResponse;
import org.eclipse.jetty.security.AuthenticationState;
import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.Constraint.Authorization;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.security.internal.DefaultUserIdentity;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Session;
import org.eclipse.jetty.util.Callback;

import com.sap.cloud.security.servlet.TokenAuthenticationResult;
import com.sap.cloud.security.servlet.TokenAuthenticator;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
/**
 * Decorates the TokenAuthenticator and adapts it to Jetty.
 */
public class JettyTokenAuthenticator implements Authenticator {

	private final TokenAuthenticator tokenAuthenticator;

	public JettyTokenAuthenticator(TokenAuthenticator tokenAuthenticator) {
		this.tokenAuthenticator = tokenAuthenticator;
	}

	@Override
	public void setConfiguration(Configuration configuration) {
	}

	@Override
	public String getAuthenticationType() {
		return "Token";
	}

	@Override
	public Authorization getConstraintAuthentication(String pathInContext, Authorization existing, Function<Boolean, Session> getSession) {
		return Authorization.ANY_USER;
	}

	@Override
	public AuthenticationState validateRequest(Request request, Response response, Callback callback) throws ServerAuthException {
		ServletRequest servletRequest = request instanceof ServletContextRequest scr ? scr.getServletApiRequest() : null;
		ServletResponse servletResponse = response instanceof ServletContextResponse scr ? scr.getServletApiResponse() : null;

		TokenAuthenticationResult tokenAuthenticationResult = tokenAuthenticator.validateRequest(servletRequest, servletResponse);
		if (tokenAuthenticationResult.isAuthenticated()) {
			return createAuthentication(tokenAuthenticationResult);
		} else {
			Response.writeError(request, response, callback, HttpServletResponse.SC_UNAUTHORIZED, tokenAuthenticationResult.getUnauthenticatedReason());
			return AuthenticationState.SEND_FAILURE;
		}
	}

	private AuthenticationState createAuthentication(TokenAuthenticationResult tokenAuthentication) {
		Principal principal = tokenAuthentication.getPrincipal();
		Set<Principal> principals = new HashSet<>();
		principals.add(principal);
		Subject subject = new Subject(true, principals, new HashSet<>(), new HashSet<>());
		String[] scopes = tokenAuthentication.getScopes().toArray(new String[0]);
		return new LoginAuthenticator.UserAuthenticationSucceeded(getAuthenticationType(), new DefaultUserIdentity(subject, principal, scopes));
	}
}
