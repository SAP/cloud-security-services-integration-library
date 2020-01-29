package com.sap.cloud.security.token;

import javax.annotation.Nonnull;
import java.util.List;

public interface AccessToken extends Token {

	/**
	 * Returns the list of the claim "scope".
	 *
	 * @return the list of the claim scope or empty list.
	 */
	List<String> getScopes();

	/**
	 * Checks if a scope is available in the access token.
	 *
	 * @param scope
	 *            name of the scope
	 * @return true if scope is available
	 */
	boolean hasScope(String scope);

	/**
	 * Check if a local scope is available in the authentication token.
	 * The exact definition of a local scope depends on the specific
	 * token implementation.
	 *
	 * @param scope
	 *            name of local scope
	 * @return true if local scope is available
	 **/
	boolean hasLocalScope(@Nonnull String scope);
}
