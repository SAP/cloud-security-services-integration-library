package com.sap.cloud.security.token;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Set;

/**
 * Represents an access token in the format of a JSON Web Token (not a short opaque token).
 * In difference to a ID token the access token has no/less information about the user but
 * has information about the authorities (scopes).
 */
public interface AccessToken extends Token {

	/**
	 * Returns the list of the claim "scope".
	 *
	 * @return the list of the claim scope or empty list.
	 */
	Set<String> getScopes();

	/**
	 * Checks if a scope is available in the access token.
	 *
	 * @param scope
	 *            name of the scope
	 * @return true if scope is available
	 */
	boolean hasScope(String scope);

	/**
	 * Check if a local scope is available in the authentication token. The exact
	 * definition of a local scope depends on the specific token implementation.
	 *
	 * @param scope
	 *            name of local scope
	 * @return true if local scope is available
	 **/
	boolean hasLocalScope(@Nonnull String scope);

	/**
	 * Get the encoded jwt token with "Bearer " prefix, e.g. for
	 * Authorization Http Header.
	 *
	 * <p>
	 * Never expose this token via log or via HTTP.
	 *
	 * @return the encoded token.
	 */
	String getBearerTokenValue();

	/**
	 * Returns the grant type of the jwt token. <br>
	 *
	 * @return the grant type
	 **/
	@Nullable
	GrantType getGrantType();
}
