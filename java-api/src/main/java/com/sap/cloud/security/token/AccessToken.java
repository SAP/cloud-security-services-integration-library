package com.sap.cloud.security.token;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;
import java.util.Set;

/**
 * Represents an access token in the format of a JSON Web Token (not a short
 * opaque token). In difference to a ID token the access token has no/less
 * information about the user but has information about the authorities
 * (scopes).
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
	 * Returns the grant type of the jwt token. <br>
	 *
	 * @return the grant type
	 **/
	@Nullable
	GrantType getGrantType();

	/**
	 * Returns the String value of attribute of claim. <br>
	 * <code>
	 *     "claimName": {
	 *         "attributeName": "attributeValueAsString"
	 *     },
	 *     </code> Example: <br>
	 * <code>
	 *     import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;
	 *
	 *     token.getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, EXTERNAL_ATTRIBUTE_SUBACCOUNTID);
	 *     </code>
	 * 
	 * @return the String value of attribute of claim.
	 **/
	@Nullable
	default String getAttributeFromClaimAsString(String claimName, String attributeName) {
		return Optional.ofNullable(getClaimAsJsonObject(claimName))
				.map(claim -> claim.getAsString(attributeName))
				.orElse(null);
	}
}
