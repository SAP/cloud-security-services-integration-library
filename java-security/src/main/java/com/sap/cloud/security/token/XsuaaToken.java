/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static com.sap.cloud.security.token.TokenClaims.USER_NAME;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;

/**
 * Decodes and parses encoded access token (JWT) for the Xsuaa identity service
 * and provides access to token header parameters and claims.
 */
public class XsuaaToken extends AbstractToken implements AccessToken {
	static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
	static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>
	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaToken.class);
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
	 * Get unique principal name of a user.
	 *
	 * @param origin
	 *            of the access token
	 * @param userName
	 *            of the access token
	 * @return unique principal name or <code>null</code> if origin or user name is
	 *         <code>null</code> or empty. Origin must also not contain a '/'
	 *         character.
	 */
	static String getUniquePrincipalName(String origin, String userName) {
		if (isNullOrEmpty(origin)) {
			LOGGER.warn("origin claim not set in JWT. Cannot create unique user name. Returning null.");
			return null;
		}
		if (isNullOrEmpty(userName)) {
			LOGGER.warn("user_name claim not set in JWT. Cannot create unique user name. Returning null.");
			return null;
		}
		if (origin.contains("/")) {
			LOGGER.warn(
					"Illegal '/' character detected in origin claim of JWT. Cannot create unique user name. Returning null.");
			return null;
		}
		return String.format(UNIQUE_USER_NAME_FORMAT, origin, userName);
	}

	private static boolean isNullOrEmpty(String string) {
		return string == null || string.isEmpty();
	}

	/**
	 * Configures a scope converter, e.g. required for the
	 * {@link #hasLocalScope(String)}
	 *
	 * @param converter
	 *            the scope converter, e.g. {@link XsuaaScopeConverter}
	 *
	 * @return the token itself
	 */
	public XsuaaToken withScopeConverter(@Nullable ScopeConverter converter) {
		this.scopeConverter = converter;
		return this;
	}

	@Override
	public Set<String> getScopes() {
		LinkedHashSet<String> scopes = new LinkedHashSet<>();
		scopes.addAll(getClaimAsStringList(TokenClaims.XSUAA.SCOPES));
		return scopes;
	}

	@Override
	public Principal getPrincipal() {
		String principalName;
		switch (getGrantType()) {
		case CLIENT_CREDENTIALS:
		case CLIENT_X509:
			principalName = String.format(UNIQUE_CLIENT_NAME_FORMAT, getClientId());
			break;
		default:
			principalName = getUniquePrincipalName(getClaimAsString(ORIGIN), getClaimAsString(USER_NAME));
			break;
		}
		return createPrincipalByName(principalName);
	}

	@Override
	public Service getService() {
		return Service.XSUAA;
	}

	@Override
	public boolean hasScope(String scope) {
		return getScopes().contains(scope);
	}

	/**
	 * Check if a local scope is available in the authentication token. <br>
	 * Requires a {@link ScopeConverter} to be configured with
	 * {@link #withScopeConverter(ScopeConverter)}.
	 *
	 * @param scope
	 *            name of local scope (without the appId)
	 * @return true if local scope is available
	 **/
	@Override
	public boolean hasLocalScope(@Nonnull String scope) {
		Assertions.assertNotNull(scopeConverter,
				"hasLocalScope() method requires a scopeConverter, which must not be null");
		return scopeConverter.convert(getScopes()).contains(scope);
	}

	@Override
	public GrantType getGrantType() {
		return GrantType.from(getClaimAsString(GRANT_TYPE));
	}

	/**
	 * Returns the value of the subdomain (zdn) from the external attribute ext_attr
	 * (ext_attr) claim. If the external attribute or the subdomain is missing, it
	 * returns {@code null}.
	 *
	 * @return the subdomain or {@code null}
	 */
	@Nullable
	public String getSubdomain() {
		return getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, EXTERNAL_ATTRIBUTE_ZDN);
	}

	@Override
	public String getSubaccountId() {
		return Optional.ofNullable(getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, EXTERNAL_ATTRIBUTE_SUBACCOUNTID))
				.orElse(getClaimAsString(ZONE_ID));
	}

	@Override
	public String getZoneId() {
		return Objects.nonNull(super.getZoneId()) ? super.getZoneId() : getClaimAsString(ZONE_ID);
	}

	@Override
	public String getClientId() {
		try {
			return super.getClientId();
		} catch (InvalidTokenException ex) {
			if (hasClaim(CLIENT_ID) && !getClaimAsString(CLIENT_ID).trim()
					.isEmpty()) { // required for backward compatibility for generated tokens in JUnit tests
				LOGGER.warn("Usage of 'cid' claim is deprecated and should be replaced by 'azp' or 'aud' claims");
				return getClaimAsString(CLIENT_ID);
			}
		}
		LOGGER.error("Couldn't get client id. Invalid authorized party or audience claims.");
		throw new InvalidTokenException("Couldn't get client id. Invalid authorized party or audience claims.");
	}
}
