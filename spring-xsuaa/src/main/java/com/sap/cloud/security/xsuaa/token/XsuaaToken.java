package com.sap.cloud.security.xsuaa.token;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_CLIENT_ID;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_EMAIL;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_FAMILY_NAME;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_GIVEN_NAME;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_GRANT_TYPE;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_ORIGIN;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_USER_NAME;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_ZDN;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_ZONE_ID;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.sap.cloud.security.xsuaa.tokenflows.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.util.Assert;

import net.minidev.json.JSONArray;

/**
 * Custom XSUAA token implementation.
 *
 * This class inherits Spring Security's standard Jwt implementation and can be
 * used interchangeably with it.
 */
public class XsuaaToken extends Jwt implements Token {
	private static final long serialVersionUID = -836947635254353927L;

	private static final Logger logger = LoggerFactory.getLogger(XsuaaToken.class);

	static final String GRANTTYPE_SAML2BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer";
	static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
	static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>

	static final String CLAIM_SERVICEINSTANCEID = "serviceinstanceid";
	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
	static final String CLAIM_EXTERNAL_ATTR = "ext_attr";
	static final String CLAIM_EXTERNAL_CONTEXT = "ext_ctx";

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
	public String getPassword() {
		return null;
	}

	@Override
	public String getUsername() {
		if (GRANTTYPE_CLIENTCREDENTIAL.equals(getGrantType())) {
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
					"Illegal '/' character detected in origin claim of JWT. Cannot create unique user name. Returing null.");
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
		return getClaimAsString(CLAIM_CLIENT_ID);
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

	/**
	 * Check if the authentication token contains a claim, e.g. "email".
	 * 
	 * @param claim
	 *            name of the claim
	 * @return true: attribute exists
	 */
	public boolean hasClaim(String claim) {
		return containsClaim(claim);
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
		if (claimMap == null) {
			logger.debug("Claim '{}' not found. Returning null.", claimName);
			return attributeValues;
		}

		// convert JSONArray to String[]
		JSONArray attributeJsonArray = (JSONArray) claimMap.get(attributeName);
		if (attributeJsonArray != null) {
			attributeValues = new String[attributeJsonArray.size()];
			for (int i = 0; i < attributeJsonArray.size(); i++) {
				attributeValues[i] = (String) attributeJsonArray.get(i);
			}
		}

		if (attributeValues == null) {
			logger.debug("Attribute '{}' in claim '{}' not found. Returning null.", attributeName, claimName);
			return attributeValues;
		}

		return attributeValues;
	}

}
