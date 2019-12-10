package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import java.security.Principal;
import java.util.List;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;

public class XsuaaToken extends AbstractToken {
	static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
	static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>

	private final String appId;

	public XsuaaToken(@Nonnull DecodedJwt decodedJwt, String appId) {
		super(decodedJwt);
		this.appId = appId;
	}

	public XsuaaToken(@Nonnull String accessToken, String appId) {
		super(accessToken);
		this.appId = appId;
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

	public String getAppId() {
		return appId;
	}

	public boolean hasScope(String scopeName) {
		return getScopes().contains(scopeName);
	}

}
