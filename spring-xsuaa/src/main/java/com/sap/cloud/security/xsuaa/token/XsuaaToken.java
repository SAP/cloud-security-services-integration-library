/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import com.sap.cloud.security.token.InvalidTokenException;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.*;

import static com.sap.cloud.security.token.TokenClaims.AUTHORIZATION_PARTY;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.CLIENT_ID;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.*;
import static org.springframework.util.StringUtils.hasText;

import com.sap.cloud.security.xsuaa.client.OAuth2TokenServiceConstants;

/**
 * Custom XSUAA token implementation.
 * <p>
 * This class inherits Spring Security's standard Jwt implementation and can be
 * used interchangeably with it.
 */
public class XsuaaToken extends Jwt implements Token {
	static final String GRANTTYPE_SAML2BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer";
	static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
	static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>
	static final String CLAIM_SERVICEINSTANCEID = "serviceinstanceid";
	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
	static final String CLAIM_EXTERNAL_ATTR = "ext_attr";
	static final String CLAIM_EXTERNAL_CONTEXT = "ext_ctx";
	// new with SECAUTH-806
	static final String CLAIM_SUBACCOUNT_ID = "subaccountid";
	//
	private static final long serialVersionUID = -836947635254353927L;
	private static final Logger logger = LoggerFactory.getLogger(XsuaaToken.class);
	private Collection<GrantedAuthority> authorities = Collections.emptyList();

	/**
	 * @param jwt
	 *            token
	 */
	protected XsuaaToken(Jwt jwt) {
		super(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getHeaders(), jwt.getClaims());
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return this.authorities;
	}

	@Override
	public Date getExpirationDate() {
		return getExpiresAt() != null ? Date.from(getExpiresAt()) : null;
	}

	@Override
	public Instant getExpiration() {
		return getExpiresAt();
	}

	@Override
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		if (OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_CREDENTIALS.equals(getGrantType()) ||
				OAuth2TokenServiceConstants.GRANT_TYPE_CLIENT_X509.equalsIgnoreCase(getGrantType())) {
			return String.format(UNIQUE_CLIENT_NAME_FORMAT, getClientId());
		} else {
			return getUniquePrincipalName(getOrigin(), getLogonName());
		}
	}

	@Override
	public boolean isAccountNonExpired() {
		JwtTimestampValidator validator = new JwtTimestampValidator();
		return !validator.validate(this).hasErrors();
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		JwtTimestampValidator validator = new JwtTimestampValidator();
		return validator.validate(this).hasErrors();
	}

	@Override
	public boolean isEnabled() {
		return false;
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
	public static String getUniquePrincipalName(String origin, String userLoginName) {
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
					"Illegal '/' character detected in origin claim of JWT. Cannot create unique user name. Returning null.");
			return null;
		}

		return String.format(UNIQUE_USER_NAME_FORMAT, origin, userLoginName);
	}

	/**
	 * convenient access to other claims
	 **/

	@Override
	@Nullable
	public String getLogonName() {
		return getClaimAsString(CLAIM_USER_NAME);
	}

	@Override
	@Nullable
	public String getClientId() {
		String clientId = getClaimAsString(AUTHORIZATION_PARTY);
		if (clientId == null || clientId.trim().isEmpty()) {
			List<String> audiences = getAudience();

			if (audiences != null && audiences.size() == 1) {
				return audiences.get(0);
			} else if (hasClaim(CLIENT_ID) && !getClaimAsString(CLIENT_ID).trim() // required for backward compatibility
																					// for generated tokens in JUnit
																					// tests
					.isEmpty()) {
				logger.warn("usage of 'cid' claim is deprecated and should be replaced by 'azp' or 'aud' claims");
				return getClaimAsString(CLIENT_ID);
			}
			logger.error("Couldn't get client id. Invalid authorized party or audience claims.");
			throw new InvalidTokenException(
					"Couldn't get client id. Invalid authorized party or audience claims.");
		} else {
			return clientId;
		}
	}

	@Override
	public String getGivenName() {
		String externalAttribute = getStringAttributeFromClaim(CLAIM_GIVEN_NAME, CLAIM_EXTERNAL_ATTR);
		return externalAttribute != null ? externalAttribute : getClaimAsString(CLAIM_GIVEN_NAME);
	}

	@Override
	@Nullable
	public String getFamilyName() {
		String externalAttribute = getStringAttributeFromClaim(CLAIM_FAMILY_NAME, CLAIM_EXTERNAL_ATTR);
		return externalAttribute != null ? externalAttribute : getClaimAsString(CLAIM_FAMILY_NAME);
	}

	@Override
	public String getEmail() {
		return getClaimAsString(CLAIM_EMAIL);
	}

	@Override
	public String getOrigin() {
		return getClaimAsString(CLAIM_ORIGIN);
	}

	@Override
	public String getGrantType() {
		return getClaimAsString(CLAIM_GRANT_TYPE);
	}

	@Override
	public String getSubaccountId() {
		String externalAttribute = getStringAttributeFromClaim(CLAIM_SUBACCOUNT_ID, CLAIM_EXTERNAL_ATTR);
		return !hasText(externalAttribute) ? getClaimAsString(CLAIM_ZONE_ID) : externalAttribute;
	}

	@Override
	public String getZoneId() {
		return getClaimAsString(CLAIM_ZONE_ID);
	}

	@Override
	public String getSubdomain() {
		return getStringAttributeFromClaim(CLAIM_ZDN, CLAIM_EXTERNAL_ATTR);
	}

	@Override
	public String toString() {
		return getUsername();
	}

	@Nullable
	@Override
	public String[] getXSUserAttribute(String attributeName) {
		String[] attributeValue = getStringListAttributeFromClaim(attributeName, CLAIM_EXTERNAL_CONTEXT);
		return attributeValue != null ? attributeValue
				: getStringListAttributeFromClaim(attributeName, TokenClaims.CLAIM_XS_USER_ATTRIBUTES);
	}

	@Override
	public String getAdditionalAuthAttribute(String attributeName) {
		return getStringAttributeFromClaim(attributeName, CLAIM_ADDITIONAL_AZ_ATTR);
	}

	@Override
	public String getCloneServiceInstanceId() {
		return getStringAttributeFromClaim(CLAIM_SERVICEINSTANCEID, CLAIM_EXTERNAL_ATTR);
	}

	@Override
	public String getAppToken() {
		return getTokenValue();
	}

	@Override
	public Collection<String> getScopes() {
		List<String> scopesList = getClaimAsStringList(TokenClaims.CLAIM_SCOPES);
		return scopesList != null ? scopesList : Collections.emptyList();
	}

	void setAuthorities(Collection<GrantedAuthority> authorities) {
		Assert.notNull(authorities, "authorities are required");
		this.authorities = authorities;
	}

	private String getStringAttributeFromClaim(String attributeName, String claimName) {
		Map<String, Object> attribute = getClaimAsMap(claimName);
		return attribute == null ? null : (String) attribute.get(attributeName);
	}

	private String[] getStringListAttributeFromClaim(String attributeName, String claimName) {
		String[] attributeValues = null;

		Map<String, Object> claimMap = getClaimAsMap(claimName);
		if (claimMap == null || !claimMap.containsKey(attributeName)) {
			logger.debug("Claim '{}' not found. Returning null.", claimName);
			return attributeValues;
		}

		// convert JSONArray to String[]
		JSONArray attributeJsonArray = new JSONArray((ArrayList) claimMap.get(attributeName));
		attributeValues = new String[attributeJsonArray.length()];
		for (int i = 0; i < attributeJsonArray.length(); i++) {
			attributeValues[i] = (String) attributeJsonArray.get(i);
		}

		if (attributeValues.length == 0) {
			logger.debug("Attribute '{}' in claim '{}' not found. Returning empty list.", attributeName, claimName);
			return attributeValues;
		}

		return attributeValues;
	}

}
