/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.servlet;

import com.sap.cloud.security.token.Token;

import javax.annotation.Nullable;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;

/**
 * Class that represents the result of the authentication check performed by a
 * {@link TokenAuthenticator}.
 */
public interface TokenAuthenticationResult {
	/**
	 * The token that was checked for authentication.
	 *
	 * @return the token.
	 */
	@Nullable
	Token getToken();

	/**
	 * The principal associated with the request.
	 *
	 * @return the principal.
	 */
	@Nullable
	Principal getPrincipal();

	/**
	 * The authentication scopes. Can be empty.
	 *
	 * @return the scopes as a list of strings. Returns empty collection by default.
	 */
	default Collection<String> getScopes() {
		return Collections.emptyList();
	}

	/**
	 * @return false if a reason for "unauthenticated" is given.
	 */
	default boolean isAuthenticated() {
		return getUnauthenticatedReason().isEmpty();
	}

	/**
	 * If not authenticated, this returns the reason why as text.
	 *
	 * @return the textual description why the request was not authenticated. Empty
	 *         string if authenticated.
	 */
	default String getUnauthenticatedReason() {
		return "";
	}
}
