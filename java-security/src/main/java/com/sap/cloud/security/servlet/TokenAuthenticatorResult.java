/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.xsuaa.Assertions;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;

/**
 * Class to collect the result of the authentication performed by a
 * {@link TokenAuthenticator}.
 */
class TokenAuthenticatorResult implements TokenAuthenticationResult {

	private Collection<String> scopes = Collections.emptyList();
	private Token token = null;
	private String reason = "";

	private TokenAuthenticatorResult() {
		// use static create methods
	}

	/**
	 * Creates an unauthenticated result with a reason.
	 * 
	 * @param reason
	 *            the reason why the request is not authenticated.
	 * @return a {@link TokenAuthenticationResult}.
	 */
	public static TokenAuthenticationResult createUnauthenticated(String reason) {
		Assertions.assertHasText(reason, "Reason must contain text");
		TokenAuthenticatorResult result = new TokenAuthenticatorResult();
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
	public static TokenAuthenticationResult createAuthenticated(Collection<String> scopes, Token token) {
		TokenAuthenticatorResult result = new TokenAuthenticatorResult();
		result.scopes = scopes;
		result.token = token;
		return result;
	}

	/**
	 * The token that was checked for authentication.
	 * 
	 * @return the token.
	 */
	@Override
	public Token getToken() {
		return token;
	}

	/**
	 * The principal associated with the request.
	 * 
	 * @return the principal.
	 */
	@Override
	public Principal getPrincipal() {
		return token.getPrincipal();
	}

	/**
	 * The authentication scopes. Can be empty.
	 * 
	 * @return the scopes as a list of strings.
	 */
	@Override
	public Collection<String> getScopes() {
		return scopes;
	}

	/**
	 * If not authenticated, this returns the reason why as text.
	 * 
	 * @return the textual description why the request was not authenticated. Empty
	 *         string if authenticated.
	 */
	@Override
	public String getUnauthenticatedReason() {
		return reason;
	}
}
