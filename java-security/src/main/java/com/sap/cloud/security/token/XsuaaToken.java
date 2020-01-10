package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import java.security.Principal;
import java.util.List;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;

/**
 * Decodes and parses encoded access token (JWT) for the Xsuaa identity
 * service and provides access to token header parameters and claims.
 */
public class XsuaaToken extends AbstractToken {
	static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
	static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>
	private ScopeConverter scopeConverter;

	/**
	 * Creates an instance.
	 *
	 * @param decodedJwt
	 *            the decoded jwt
	 */
	public XsuaaToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	/**
	 * Creates an instance.
	 *
	 * @param accessToken
	 *            the encoded access token, e.g. from the {@code Authorization}
	 *            header.
	 */
	public XsuaaToken(@Nonnull String accessToken) {
		super(accessToken);
	}

	/**
	 * Configures a scope converter, e.g. required for the
	 * {@link #hasLocalScope(String)}
	 *
	 * @param converter
	 *            the scope converter, e.g. {@link XsuaaScopeConverter}
	 */
	public XsuaaToken withScopeConverter(ScopeConverter converter) {
		this.scopeConverter = converter;
		return this;
	}

	/**
	 * Get unique principal name of a user.
	 *
	 * @param origin
	 *            of the access token
	 * @param userLoginName
	 *            of the access token
	 * @return unique principal name
	 *
	 * @throws IllegalArgumentException
	 */
	static String getUniquePrincipalName(String origin, String userLoginName) {
		Assertions.assertHasText(origin,
				"Origin claim not set in JWT. Cannot create unique user name. Returning null.");
		Assertions.assertHasText(userLoginName,
				"User login name claim not set in JWT. Cannot create unique user name. Returning null.");

		if (origin.contains("/")) {
			throw new IllegalArgumentException(
					"Illegal '/' character detected in origin claim of JWT. Cannot create unique user name. Returing null.");
		}

		return String.format(UNIQUE_USER_NAME_FORMAT, origin, userLoginName);
	}

	/**
	 * Returns the list of the claim "scope".
	 * 
	 * @return the list of the claim scope or empty list.
	 */
	public List<String> getScopes() {
		return getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
	}

	@Override
	public Principal getPrincipal() {
		String principalName;
		switch (getClaimAsString(GRANT_TYPE)) {
		case OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS:
		case OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_X509:
			principalName = String.format(UNIQUE_CLIENT_NAME_FORMAT, getClaimAsString(CLIENT_ID));
			break;
		default:
			principalName = getUniquePrincipalName(getClaimAsString(ORIGIN), getClaimAsString(USER_NAME));
			break;
		}
		return () -> principalName;
	}

	@Override
	public Service getService() {
		return Service.XSUAA;
	}

	/**
	 * Checks if a scope is available in the access token.
	 * 
	 * @param scope
	 *            name of the scope
	 * @return true if scope is available
	 */
	public boolean hasScope(String scope) {
		return getScopes().contains(scope);
	}

	/**
	 * Check if a local scope is available in the authentication token. <br>
	 * Requires a {@link ScopeConverter} to be configured with {@link #withScopeConverter(ScopeConverter)}.
	 *
	 * @param scope
	 *            name of local scope (without the appId)
	 * @return true if local scope is available
	 **/
	public boolean hasLocalScope(@Nonnull String scope) {
		Assertions.assertNotNull(scopeConverter, "scopeConverter must not be null");
		return scopeConverter.convert(getScopes()).contains(scope);
	}
}
