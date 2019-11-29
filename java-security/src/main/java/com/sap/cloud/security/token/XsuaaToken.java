package com.sap.cloud.security.token;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.CLIENT_ID;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.GRANT_TYPE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.ORIGIN;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.USER_NAME;

import com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.security.Principal;
import java.util.List;

public class XsuaaToken extends AbstractToken {
	static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
	static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>

	public XsuaaToken(@Nonnull DecodedJwt decodedJwt) {
		super(decodedJwt);
	}

	public XsuaaToken(@Nonnull String accessToken) {
		super(accessToken);
	}

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

	/**
	 * Get unique principal name of a user.
	 *
	 * @param origin
	 *            of the access token
	 * @param userLoginName
	 *            of the access token
	 * @return unique principal name
	 */
	@Nullable
	String getUniquePrincipalName(String origin, String userLoginName) {
		if (origin == null) {
			logger.warn("Origin claim not set in JWT. Cannot create unique user name. Returning null.");
			return null;
		}

		if (userLoginName == null) {
			logger.warn("User login name claim not set in JWT. Cannot create unique user name. Returning null.");
			return null;
		}

		if (origin.contains("/")) {
			logger.warn(
					"Illegal '/' character detected in origin claim of JWT. Cannot create unique user name. Returing null.");
			return null;
		}

		return String.format(UNIQUE_USER_NAME_FORMAT, origin, userLoginName);
	}

}
