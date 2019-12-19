package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nullable;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Class to collect the result of the authentication performed by a
 * {@link TokenAuthenticator}.
 */
public class TokenAuthenticationResult {

	private final Collection<String> scopes;
	private final Principal principal;
	private final Token token;
	private final String reason;

	private TokenAuthenticationResult(Principal principal, Collection<String> scopes, Token token) {
		this.principal = principal;
		this.token = token;
		this.scopes = scopes;
		this.reason = "";
	}

	private TokenAuthenticationResult(String reason) {
		this.principal = null;
		this.token = null;
		this.scopes = new ArrayList<>();
		this.reason = reason;
	}

	/**
	 * Creates an unauthenticated result with a reason.
	 * 
	 * @param reason
	 *            the reason why the request is not authenticated.
	 * @return a {@link TokenAuthenticationResult}.
	 */
	public static final TokenAuthenticationResult createUnauthenticated(String reason) {
		Assertions.assertHasText(reason, "Reason must contain text");
		return new TokenAuthenticationResult(reason);
	}

	/**
	 *
	 * @param principal
	 *            the principal associated with the request.
	 * @param scopes
	 *            the authentication scopes. Can be empty.
	 * @param token
	 *            the token that was checked for authentication.
	 * @return a {@link TokenAuthenticationResult}.
	 */
	public static TokenAuthenticationResult createAuthenticated(Principal principal, Collection<String> scopes,
			Token token) {
		return new TokenAuthenticationResult(principal, scopes, token);
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
		return principal;
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
