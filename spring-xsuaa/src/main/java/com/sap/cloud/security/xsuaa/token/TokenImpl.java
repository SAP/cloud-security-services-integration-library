package com.sap.cloud.security.xsuaa.token;

import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.sap.xs2.security.container.XSTokenRequestImpl;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.util.Assert;

import com.sap.xsa.security.container.XSTokenRequest;
import com.sap.xsa.security.container.XSUserInfoException;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.web.client.RestTemplate;

public class TokenImpl implements Token {

	static final String GRANTTYPE_SAML2BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer";
	static final String UNIQUE_USER_NAME_FORMAT = "user/%s/%s"; // user/<origin>/<logonName>
	static final String UNIQUE_CLIENT_NAME_FORMAT = "client/%s"; // client/<clientid>

	static final String CLAIM_USER_NAME = "user_name";
	static final String CLAIM_GIVEN_NAME = "given_name";
	static final String CLAIM_FAMILY_NAME = "family_name";
	static final String CLAIM_EMAIL = "email";
	static final String CLAIM_CLIENT_ID = "cid";
	static final String CLAIM_ORIGIN = "origin";
	static final String CLAIM_GRANT_TYPE = "grant_type";
	static final String CLAIM_ZDN = "zdn";
	static final String CLAIM_AUDIENCE = "aud";
	static final String CLAIM_ZONE_ID = "zid";
	static final String CLAIM_SERVICEINSTANCEID = "serviceinstanceid";

	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
	static final String CLAIM_EXTERNAL_ATTR = "ext_attr";
	static final String CLAIM_EXTERNAL_CONTEXT = "ext_ctx";

	private final Log logger = LogFactory.getLog(getClass());
	private String appId = null;
	private Jwt jwt;

	/**
	 * @param jwt
	 *            token
	 * @param appId
	 *            app name
	 */
	protected TokenImpl(Jwt jwt, String appId) {
		this.appId = appId;
		this.jwt = jwt;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		TokenAuthenticationConverter converter = new TokenAuthenticationConverter(appId);
		return converter.extractAuthorities(jwt);
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
		return !validator.validate(jwt).hasErrors();
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		JwtTimestampValidator validator = new JwtTimestampValidator();
		return validator.validate(jwt).hasErrors();
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
	 * @param logonName
	 *            of the access token
	 * @return unique principal name
	 */
	public static String getUniquePrincipalName(String origin, String logonName) {
		Assert.notNull(origin, "Origin required");
		Assert.notNull(logonName, "LogonName required");
		Assert.doesNotContain(origin, "/", CLAIM_ORIGIN + " must not contain '/' characters");
		return String.format(UNIQUE_USER_NAME_FORMAT, origin, logonName);
	}

	/**
	 * convenient access to other claims
	 **/

	@Override
	@Nullable
	public String getLogonName() {
		raiseMethodUnsupportedWhenClientCredentialGrantType("getLogonName");
		return jwt.getClaimAsString(CLAIM_USER_NAME);
	}

	@Override
	@Nullable
	public String getClientId() {
		return jwt.getClaimAsString(CLAIM_CLIENT_ID);
	}

	@Override
	public String getGivenName() {
		raiseMethodUnsupportedWhenClientCredentialGrantType("getGivenName");
		String externalAttribute = getExternalAttribute(CLAIM_GIVEN_NAME);
		return externalAttribute != null ? externalAttribute : jwt.getClaimAsString(CLAIM_GIVEN_NAME);
	}

	@Override
	@Nullable
	public String getFamilyName() {
		raiseMethodUnsupportedWhenClientCredentialGrantType("getFamilyName");
		String externalAttribute = getExternalAttribute(CLAIM_FAMILY_NAME);
		return externalAttribute != null ? externalAttribute : jwt.getClaimAsString(CLAIM_FAMILY_NAME);
	}

	@Override
	public String getEmail() {
		raiseMethodUnsupportedWhenClientCredentialGrantType("getEmail");
		return jwt.getClaimAsString(CLAIM_EMAIL);
	}

	@Override
	public String getOrigin() {
		raiseMethodUnsupportedWhenClientCredentialGrantType("getOrigin");
		return jwt.getClaimAsString(CLAIM_ORIGIN);
	}

	@Override
	public String getGrantType() {
		return jwt.getClaimAsString(CLAIM_GRANT_TYPE);
	}

	@Override
	public String getSubaccountId() {
		return jwt.getClaimAsString(CLAIM_ZONE_ID);
	}

	@Override
	public String getSubdomain() {
		return getExternalAttribute(CLAIM_ZDN);
	}

	@Override
	public String toString() {
		return getUsername();
	}

	@Nullable
	@Override
	public String[] getXSUserAttribute(String attributeName) {
		raiseMethodUnsupportedWhenClientCredentialGrantType("getAttribute");
		return getMultiValueAttributeFromExtClaim(attributeName, CLAIM_XS_USER_ATTRIBUTES);
	}

	@Override
	public String getAdditionalAuthAttribute(String attributeName) {
		return getAttributeFromClaim(attributeName, CLAIM_ADDITIONAL_AZ_ATTR);
	}

	@Nullable
	private String[] getMultiValueAttributeFromExtClaim(String attributeName, String claimName) {
		String[] attributeValues = null;
		if (hasClaim(CLAIM_EXTERNAL_CONTEXT)) {
			JSONObject jsonExtern = (JSONObject) jwt.getClaimAsMap(CLAIM_EXTERNAL_CONTEXT);
			JSONObject jsonObject = (JSONObject) jsonExtern.get(claimName);
			JSONArray jsonArray = (JSONArray) jsonObject.get(attributeName);
			int length = jsonArray != null ? jsonArray.size() : 0;
			attributeValues = new String[length];
			for (int i = 0; i < length; i++) {
				attributeValues[i] = (String) jsonArray.get(i);
			}
		} else if (hasClaim(claimName)) {
			return getMultiValueAttributeFromClaim(attributeName, claimName);
		}
		return attributeValues;
	}

	private String[] getMultiValueAttributeFromClaim(String attributeName, String claimName) {
		String[] attributeValues = new String[0];
		Map<String, Object> jsonObject = jwt.getClaimAsMap(claimName);
		Assert.state(jsonObject != null, "Invalid value of " + claimName);
		JSONArray jsonArray = (JSONArray) jsonObject.get(attributeName);
		if (jsonArray != null) {
			int length = jsonArray.size();
			attributeValues = new String[length];
			for (int i = 0; i < length; i++) {
				attributeValues[i] = (String) jsonArray.get(i);
			}
		}
		return attributeValues;
	}

	@Override
	public String getCloneServiceInstanceId() {
		return getExternalAttribute(CLAIM_SERVICEINSTANCEID);
	}

	@Override
	public String getAppToken() {
		return jwt.getTokenValue();
	}

	@Override
	public String requestToken(XSTokenRequest tokenRequest) throws URISyntaxException {
		Assert.notNull(tokenRequest, "tokenRequest argument is required");
		Assert.isTrue(tokenRequest.isValid(), "tokenRequest is not valid");

		RestTemplate restTemplate = tokenRequest instanceof XSTokenRequestImpl ? ((XSTokenRequestImpl) tokenRequest).getRestTemplate() : null;

		XsuaaTokenExchanger tokenExchanger = new XsuaaTokenExchanger(restTemplate, this);
		try {
			return tokenExchanger.requestToken(tokenRequest);
		} catch (XSUserInfoException e) {
			logger.error("Error occured during token request", e);
			return null;
		}
	}

	@Override
	public Collection<String> getScopes() {
		List<String> scopesList = jwt.getClaimAsStringList(Token.CLAIM_SCOPES);
		return scopesList != null ? scopesList : Collections.emptyList();
	}

	/**
	 * Check if the authentication token contains a claim, e.g. "email".
	 * @param claim
	 *			name of the claim
	 * @return true: attribute exists
	 */
	public boolean hasClaim(String claim) {
		return jwt.containsClaim(claim);
	}


	/**
	 * For custom access to the claims of the authentication token.
	 * 
	 * @return
	 */
	ClaimAccessor getClaimAccessor() {
		return jwt;
	}

	private void raiseMethodUnsupportedWhenClientCredentialGrantType(String method) {
		String errorMessage = "Method %s() is not supported for grant type GRANTTYPE_CLIENTCREDENTIAL";
		Assert.state(getGrantType() != GRANTTYPE_CLIENTCREDENTIAL, String.format(errorMessage, method));
	}

	private String getExternalAttribute(String attributeName) {
		return getAttributeFromClaim(attributeName, CLAIM_EXTERNAL_ATTR);
	}

	private String getAttributeFromClaim(String attributeName, String claimName) {
		Map<String, Object> externalAttribute = jwt.getClaimAsMap(claimName);
		return externalAttribute == null ? null : (String) externalAttribute.get(attributeName);
	}

}
