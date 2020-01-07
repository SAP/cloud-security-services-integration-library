package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nullable;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;

/**
 * Class to collect the result of the authentication performed by a
 * {@link TokenAuthenticator}.
 */
public class TokenAuthenticationResult {

	private Collection<String> scopes = Collections.emptyList();
	private Token token = null;
	private String reason = "";

	/**
	 * Creates an unauthenticated result with a reason.
	 * 
	 * @param reason
	 *            the reason why the request is not authenticated.
	 * @return a {@link TokenAuthenticationResult}.
	 */
	public static final TokenAuthenticationResult createUnauthenticated(String reason) {
		Assertions.assertHasText(reason, "Reason must contain text");
		TokenAuthenticationResult result = new TokenAuthenticationResult();
		result.reason = reason;
		return result;
	}

	/**
	 * @param scopes
	 *            the authentication scopes. Can be empty.
	 * @param token
	 *            the token that was checked for authentication.
	 * @return a {@link TokenAuthenticationResult}.
	 */
	public static TokenAuthenticationResult authenticated(Collection<String> scopes, Token token) {
		TokenAuthenticationResult result = new TokenAuthenticationResult();
		result.scopes = scopes;
		result.token = token;
		return result;
	}

	/**
	 * The token that was checked for authentication.
	 * 
	 * @return the token.
	 */
	@Nullable
	public Token getToken() {
		return token;
	}

	/**
	 * The principal associated with the request.
	 * 
	 * @return the principal.
	 */
	@Nullable
	public Principal getPrincipal() {
		return token.getPrincipal();
	}

	/**
	 * The authentication scopes. Can be empty.
	 * 
	 * @return the scopes as a list of strings.
	 */
	public Collection<String> getScopes() {
		return scopes;
	}

	/**
	 * @return true if authenticated.
	 */
	public boolean isAuthenticated() {
		return reason.isEmpty();
	}

	/**
	 * If not authenticated, this returns the reason why as text.
	 * 
	 * @return the textual description why the request was not authenticated. Empty
	 *         string if authenticated.
	 */
	public String getUnauthenticatedReason() {
		return reason;
	}
}
