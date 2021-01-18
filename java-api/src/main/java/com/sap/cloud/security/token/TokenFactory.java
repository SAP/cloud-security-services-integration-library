package com.sap.cloud.security.token;

/**
 * Represents a {@link com.sap.cloud.security.token.Token}Token creation
 * interface.
 */
public interface TokenFactory {

	/**
	 * Returns a token interface for the given JWT token
	 *
	 * @param jwtToken
	 *            the encoded JWT token, e.g. from the Authorization Header
	 * @return the new token instance
	 */
	Token create(String jwtToken);

}
