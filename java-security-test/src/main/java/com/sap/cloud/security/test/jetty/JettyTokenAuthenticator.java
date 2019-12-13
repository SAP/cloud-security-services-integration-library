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
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

public class JettyTokenAuthenticator implements Authenticator {

	private static final Logger logger = LoggerFactory.getLogger(JettyTokenAuthenticator.class);

	private final TokenAuthenticator tokenAuthenticator;

	public JettyTokenAuthenticator(TokenAuthenticator tokenAuthenticator) {
		this.tokenAuthenticator = tokenAuthenticator;
	}

	@Override
	public Authentication validateRequest(ServletRequest request, ServletResponse response, boolean mandatory) {
		TokenAuthenticationResult tokenAuthenticationResult = tokenAuthenticator.validateRequest(request, response);
		return tokenAuthenticationResult.isAuthenticated() ?
				createAuthentication(tokenAuthenticationResult) :
				Authentication.UNAUTHENTICATED;
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
