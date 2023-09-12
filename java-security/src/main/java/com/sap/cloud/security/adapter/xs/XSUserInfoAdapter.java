/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.adapter.xs;

import com.sap.cloud.security.config.ClientCredentials;
import com.sap.cloud.security.config.ClientIdentity;
import com.sap.cloud.security.config.Environments;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.GrantType;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.client.DefaultOAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.client.XsuaaOAuth2TokenService;
import com.sap.cloud.security.xsuaa.tokenflows.TokenFlowException;
import com.sap.cloud.security.xsuaa.tokenflows.XsuaaTokenFlows;
import com.sap.xsa.security.container.XSTokenRequest;
import com.sap.xsa.security.container.XSUserInfo;
import com.sap.xsa.security.container.XSUserInfoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.*;
import java.util.function.Supplier;

import static com.sap.cloud.security.token.TokenClaims.*;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;

/**
 * This class implements the {@link XSUserInfo} interface by wrapping and
 * delegating calls to an {@link AccessToken}.
 *
 * Other implementations of {@link XSUserInfo} support loading the token from
 * the the spring security context holder. This is not supported by this class!
 * It also does not support the SAPAuthorizationExtension.
 *
 */
public class XSUserInfoAdapter implements XSUserInfo {

	static final String EXTERNAL_CONTEXT = "ext_ctx";
	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
	static final String XS_SYSTEM_ATTRIBUTES = "xs.system.attributes";
	static final String HDB_NAMEDUSER_SAML = "hdb.nameduser.saml";
	static final String SERVICEINSTANCEID = "serviceinstanceid";
	static final String SYSTEM = "SYSTEM";
	static final String HDB = "HDB";

	private static final Logger LOGGER = LoggerFactory.getLogger(XSUserInfoAdapter.class);
	private static final String INVALID_USER_ATTRIBUTE = "Invalid user attribute ";

	private final AccessToken accessToken;
	private final OAuth2ServiceConfiguration configuration;
	/**
	 * Use {@link #getOrCreateOAuth2TokenService()} for access.
	 */
	private OAuth2TokenService oAuth2TokenService;

	public XSUserInfoAdapter(Object accessToken) {
		this(accessToken, Environments.getCurrent().getXsuaaConfiguration());
	}

	public XSUserInfoAdapter(AccessToken accessToken) {
		this(accessToken, Environments.getCurrent().getXsuaaConfiguration());
	}

	XSUserInfoAdapter(Object accessToken, OAuth2ServiceConfiguration configuration) {
		if (!(accessToken instanceof AccessToken)) {
			String type = Objects.isNull(accessToken) ? null : accessToken.getClass().getName();
			throw new XSUserInfoException("token is of instance " + type
					+ " but needs to be an instance of AccessToken.");
		}
		this.accessToken = (AccessToken) accessToken;
		this.configuration = configuration;
	}

	/**
	 * Loading the token from the security context like this is not supported!
	 *
	 * XSUserInfoAdapter() { Authentication auth =
	 * SecurityContextHolder.getContext().getAuthentication(); if (auth instanceof
	 * OAuth2Authentication) { SAPAuthorizationExtension extension =
	 * (SAPAuthorizationExtension) ((OAuth2Authentication)
	 * auth).getOAuth2Request().getExtensions().get("sap"); if (extension != null) {
	 * this.foreignMode = extension.isForeignMode(); } } }
	 */
	@Override
	public String getLogonName() {
		checkNotGrantTypeClientCredentials("getLogonName");
		return getClaimValue(USER_NAME);
	}

	@Override
	public String getGivenName() {
		checkNotGrantTypeClientCredentials("getGivenName");
		String externalAttributeName = getExternalAttribute(GIVEN_NAME);
		if (externalAttributeName == null) {
			return getClaimValue(GIVEN_NAME);
		} else {
			return externalAttributeName;
		}
	}

	@Override
	public String getFamilyName() {
		checkNotGrantTypeClientCredentials("getFamilyName");
		String externalAttributeName = getExternalAttribute(FAMILY_NAME);
		if (externalAttributeName == null) {
			return getClaimValue(FAMILY_NAME);
		} else {
			return externalAttributeName;
		}
	}

	@Override
	public String getOrigin() {
		checkNotGrantTypeClientCredentials("getOrigin");
		return getClaimValue(ORIGIN);
	}

	@Override
	public String getIdentityZone() {
		return getClaimValue(ZONE_ID);
	}

	@Override
	/**
	 * "ext_attr": { "enhancer": "XSUAA", "subaccountid": "my-subaccount-1234" },
	 */
	public String getSubaccountId() {
		return Optional.ofNullable(getExternalAttribute(EXTERNAL_ATTRIBUTE_SUBACCOUNTID))
				.orElse(getClaimValue(ZONE_ID));
	}

	@Override
	public String getZoneId() {
		if(accessToken.hasClaim(SAP_GLOBAL_APP_TID)) {
			return accessToken.getClaimAsString(SAP_GLOBAL_APP_TID);
		}

		if(accessToken.hasClaim(SAP_GLOBAL_ZONE_ID)) {
			return accessToken.getClaimAsString(SAP_GLOBAL_ZONE_ID);
		}

		return getClaimValue(ZONE_ID);
	}

	@Override
	/**
	 * "ext_attr": { "enhancer": "XSUAA", "zdn": "paas-subdomain" },
	 */
	public String getSubdomain() {
		return Optional.ofNullable(getExternalAttribute(EXTERNAL_ATTRIBUTE_ZDN)).orElse(null);
	}

	@Override
	public String getClientId() {
		return accessToken.getClientId();
	}

	@Override
	public String getJsonValue(String attribute) {
		return getClaimValue(attribute);
	}

	@Override
	public String getEmail() {
		checkNotGrantTypeClientCredentials("getEmail");
		return getClaimValue(EMAIL);
	}

	@Override
	public String getDBToken() {
		return getHdbToken();
	}

	@Override
	public String getHdbToken() {
		return getToken(SYSTEM, HDB);
	}

	@Override
	public String getAppToken() {
		return accessToken.getTokenValue();
	}

	@Override
	public String getToken(String namespace, String name) {
		if (!(getGrantType().equals(GrantType.CLIENT_CREDENTIALS.toString())) && hasAttributes() && isInForeignMode()) {
			throw new XSUserInfoException("The SecurityContext has been initialized with an access token of a "
					+ "foreign OAuth Client Id and/or Identity Zone. Furthermore, the "
					+ "access token contains attributes. Due to the fact that we want to "
					+ "restrict attribute access to the application that provides the "
					+ "attributes, the getToken() function does not return a token.");
		}
		if (!namespace.equals(SYSTEM)) {
			throw new XSUserInfoException("Invalid namespace " + namespace);
		}
		if (name.equals(HDB)) {
			String token;
			if (accessToken.hasClaim(EXTERNAL_CONTEXT)) {
				token = accessToken.getAttributeFromClaimAsString(EXTERNAL_CONTEXT, HDB_NAMEDUSER_SAML);
			} else {
				token = accessToken.getClaimAsString(HDB_NAMEDUSER_SAML);
			}
			if (token == null) {
				token = accessToken.getTokenValue();
			}
			return token;
		} else if (name.equals("JobScheduler")) {
			return accessToken.getTokenValue();
		} else {
			throw new XSUserInfoException("Invalid name " + name + " for namespace " + namespace);
		}
	}

	@Override
	public String[] getAttribute(String attributeName) {
		checkNotGrantTypeClientCredentials("getAttribute");
		return getMultiValueAttributeFromExtObject(XS_USER_ATTRIBUTES, attributeName);
	}

	@Override
	public boolean hasAttributes() {
		checkNotGrantTypeClientCredentials("hasAttributes");
		if (accessToken.hasClaim(EXTERNAL_CONTEXT)) {
			JsonObject extContext = getClaimAsJsonObject(EXTERNAL_CONTEXT);
			return extContext != null && extContext.contains(XS_USER_ATTRIBUTES) && !extContext
					.getJsonObject(EXTERNAL_CONTEXT).isEmpty();
		} else {
			JsonObject xsUserAttributes = getClaimAsJsonObject(XS_USER_ATTRIBUTES);
			return !(xsUserAttributes == null || xsUserAttributes.isEmpty());
		}
	}

	@Override
	public String[] getSystemAttribute(String attributeName) {
		return getMultiValueAttributeFromExtObject(XS_SYSTEM_ATTRIBUTES, attributeName);
	}

	@Override
	public boolean checkScope(String scope) {
		return accessToken.hasScope(scope);
	}

	@Override
	public boolean checkLocalScope(String scope) {
		try {
			return accessToken.hasLocalScope(scope);
		} catch (IllegalArgumentException e) {
			throw new XSUserInfoException(e.getMessage());
		}
	}

	@Override
	public String getAdditionalAuthAttribute(String attributeName) {
		return Optional.ofNullable(accessToken.getAttributeFromClaimAsString(CLAIM_ADDITIONAL_AZ_ATTR, attributeName))
				.orElseThrow(createXSUserInfoException(attributeName));
	}

	@Override
	public String getCloneServiceInstanceId() {
		return Optional.ofNullable(getExternalAttribute(SERVICEINSTANCEID))
				.orElseThrow(createXSUserInfoException(SERVICEINSTANCEID));
	}

	@Override
	public String getGrantType() {
		return Optional.ofNullable(accessToken.getGrantType())
				.map(GrantType::toString)
				.orElseThrow(createXSUserInfoException(GRANT_TYPE));
	}

	/**
	 * Check if a token issued for another OAuth client has been forwarded to a
	 * different client,
	 *
	 * This method does not support checking if the token can be accepted by
	 * Audience Validation.
	 *
	 * @return true if token was forwarded or if it cannot be determined.
	 */
	@Override
	public boolean isInForeignMode() {
		if (configuration == null) {
			LOGGER.info("No configuration provided -> falling back to foreignMode = true!");
			return true; // default provide OAuth2ServiceConfiguration via constructor argument
		}
		String tokenClientId, tokenIdentityZone;
		try {
			tokenClientId = getClientId();
			tokenIdentityZone = getIdentityZone();
		} catch (XSUserInfoException e) {
			LOGGER.warn("Tried to access missing attribute when checking for foreign mode", e);
			return true;
		}
		boolean clientIdsMatch = tokenClientId.equals(configuration.getClientId());
		boolean identityZonesMatch = tokenIdentityZone
				.equals(configuration.getProperty(CFConstants.XSUAA.IDENTITY_ZONE));
		boolean isApplicationPlan = tokenClientId.contains("!t");
		boolean isBrokerPlan = tokenClientId.contains("!b");

		if (clientIdsMatch && (identityZonesMatch || isApplicationPlan || isBrokerPlan)) {
			LOGGER.info(
					"Token not in foreign mode because because client ids match and identityZonesMatch={}, isApplicationPlan={} ",
					identityZonesMatch, isApplicationPlan);
			return false; // no foreign mode
		}
		// in case of broker master: check trustedclientidsuffix
		String bindingTrustedClientIdSuffix = configuration.getProperty(TRUSTED_CLIENT_ID_SUFFIX);
		if (bindingTrustedClientIdSuffix != null && tokenClientId.endsWith(bindingTrustedClientIdSuffix)) {
			LOGGER.info("Token not in foreign mode because token client id matches binding trusted client suffix");
			return false; // no foreign mode
		}
		LOGGER.info(
				"Token in foreign mode: clientIdsMatch={}, identityZonesMatch={}, isApplicationPlan={}, bindingTrustedClientIdSuffix={}",
				clientIdsMatch, identityZonesMatch, isApplicationPlan, bindingTrustedClientIdSuffix);
		return true;
	}

	@Override
	public String requestTokenForClient(String clientId, String clientSecret, String baseUaaUrl) {
		return performTokenFlow(baseUaaUrl, XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN, clientId, clientSecret,
				new HashMap<>());
	}

	@Override
	public String requestTokenForUser(String clientId, String clientSecret, String baseUaaUrl) {
		return performTokenFlow(baseUaaUrl, XSTokenRequest.TYPE_USER_TOKEN, clientId, clientSecret, new HashMap<>());
	}

	@Override
	public String requestToken(XSTokenRequest tokenRequest) {
		Assertions.assertNotNull(tokenRequest, "TokenRequest argument is required");
		if (!tokenRequest.isValid()) {
			throw new XSUserInfoException("Invalid grant type or missing parameters for requested grant type.");
		}
		String tokenEndpoint = tokenRequest.getTokenEndpoint().toString();
		String baseUaaUrl = tokenEndpoint.replace(tokenRequest.getTokenEndpoint().getPath(), "");
		Map<String, String> additionalAuthAttributes = tokenRequest.getAdditionalAuthorizationAttributes();
		return performTokenFlow(baseUaaUrl, tokenRequest.getType(), tokenRequest.getClientId(),
				tokenRequest.getClientSecret(), additionalAuthAttributes);
	}

	/**
	 * Tries to create an OAuth2TokenService and throws
	 * UnsupportedOperationException if it fails.
	 *
	 * @throws UnsupportedOperationException
	 *             if it cannot create the service.
	 * @return the created OAuth2TokenService
	 */
	private OAuth2TokenService getOrCreateOAuth2TokenService() {
		if (oAuth2TokenService == null) {
			oAuth2TokenService = tryToCreateDefaultOAuth2TokenService();
			if (oAuth2TokenService == null) {
				oAuth2TokenService = tryToCreateXsuaaOAuth2TokenService();
			}
		}
		if (oAuth2TokenService == null) {
			throw new UnsupportedOperationException("Failed to create OAuth2TokenService. "
					+ "Make sure your project has a dependency to either spring-web or apache HTTP client.");
		}
		return oAuth2TokenService;
	}

	/**
	 * This method tries to create a {@link DefaultOAuth2TokenService} instance
	 * which can fail because the required dependency (apache HTTP client) might be
	 * missing. In this case a {@link java.lang.NoClassDefFoundError} is thrown
	 * which is a {@link LinkageError} that needs to be caught in addition to
	 * exceptions!
	 *
	 * @return the {@link DefaultOAuth2TokenService} instance or null if it could
	 *         not be created.
	 */
	private OAuth2TokenService tryToCreateDefaultOAuth2TokenService() {
		LOGGER.debug("Trying to create DefaultOAuth2TokenService.");
		try {
			return new DefaultOAuth2TokenService();
		} catch (Exception | LinkageError e) {
			LOGGER.debug("Failed to create DefaultOAuth2TokenService.", e);
		}
		return null;
	}

	/**
	 *
	 * Similar to {@link #tryToCreateDefaultOAuth2TokenService()} except it tries to
	 * create {@link XsuaaOAuth2TokenService} and internally depends on spring-web.
	 *
	 * @return the {@link XsuaaOAuth2TokenService} or null if it could not be
	 *         created.
	 */
	private OAuth2TokenService tryToCreateXsuaaOAuth2TokenService() {
		LOGGER.debug("Trying to create XsuaaOAuth2TokenService.");
		try {
			return new XsuaaOAuth2TokenService();
		} catch (Exception | LinkageError e) {
			LOGGER.debug("Failed to create XsuaaOAuth2TokenService.", e);
		}
		return null;
	}

	// for tests
	void setOAuth2TokenService(OAuth2TokenService oAuth2TokenService) {
		this.oAuth2TokenService = oAuth2TokenService;
	}

	private String[] getMultiValueAttributeFromExtObject(String claimName, String attributeName) {
		List<String> values = null;

		try {
			values = accessToken.getAttributeFromClaimAsStringList(claimName, attributeName);
		} catch (JsonParsingException e) {
			String stringValue = accessToken.getAttributeFromClaimAsString(claimName, attributeName);
			values = stringValue != null
					? Collections.singletonList(stringValue)
					: Collections.emptyList();
		} finally {
			if (values == null || (values.isEmpty() && !(values instanceof ArrayList))) {
				throw new XSUserInfoException(INVALID_USER_ATTRIBUTE + attributeName);
			}
		}

		return values.toArray(new String[values.size()]);
	}

	private void checkNotGrantTypeClientCredentials(String methodName) {
		if (GrantType.CLIENT_CREDENTIALS == accessToken.getGrantType()) {
			String message = String.format("Method '%s' is not supported for grant type '%s'", methodName,
					GrantType.CLIENT_CREDENTIALS);
			throw new XSUserInfoException(message + GrantType.CLIENT_CREDENTIALS);
		}
	}

	private Supplier<XSUserInfoException> createXSUserInfoException(String attribute) {
		return () -> new XSUserInfoException(INVALID_USER_ATTRIBUTE + attribute);
	}

	private String getClaimValue(String claimname) {
		String value = accessToken.getClaimAsString(claimname);
		if (value == null) {
			throw new XSUserInfoException(INVALID_USER_ATTRIBUTE + claimname);
		}
		return value;
	}

	@Nullable
	private JsonObject getClaimAsJsonObject(String claimName) {
		try {
			return accessToken.getClaimAsJsonObject(claimName);
		} catch (JsonParsingException e) {
			throw createXSUserInfoException(claimName).get();
		}
	}

	String getExternalAttribute(String attributeName) {
		return accessToken.getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, attributeName);
	}

	/**
	 * Getter for XsuaaTokenFlows object that can be overridden for testing
	 * purposes.
	 */
	XsuaaTokenFlows getXsuaaTokenFlows(String baseUaaUrl, ClientIdentity clientIdentity) {
		return new XsuaaTokenFlows(getOrCreateOAuth2TokenService(),
				new XsuaaDefaultEndpoints(baseUaaUrl, null), clientIdentity);
	}

	private String performTokenFlow(String baseUaaUrl, int tokenRequestType, String clientId, String clientSecret,
			Map<String, String> additionalAuthAttributes) {
		try {
			ClientIdentity clientIdentity = new ClientCredentials(clientId, clientSecret);
			XsuaaTokenFlows xsuaaTokenFlows = getXsuaaTokenFlows(baseUaaUrl, clientIdentity);
			return performRequest(xsuaaTokenFlows, tokenRequestType, additionalAuthAttributes);
		} catch (RuntimeException e) {
			throw new XSUserInfoException(e.getMessage());
		}
	}

	private String performRequest(XsuaaTokenFlows xsuaaTokenFlows, int tokenRequestType,
			Map<String, String> additionalAuthAttributes) {
		switch (tokenRequestType) {
		case XSTokenRequest.TYPE_USER_TOKEN:
			return performUserTokenFlow(xsuaaTokenFlows, additionalAuthAttributes);
		case XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN:
			return performClientCredentialsFlow(xsuaaTokenFlows, additionalAuthAttributes);
		default:
			throw new XSUserInfoException(
					"Found unsupported XSTokenRequest type. The only supported types are XSTokenRequest.TYPE_USER_TOKEN and XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN.");
		}
	}

	private String performUserTokenFlow(XsuaaTokenFlows xsuaaTokenFlows, Map<String, String> additionalAuthAttributes) {
		String userToken;
		try {
			userToken = xsuaaTokenFlows.jwtBearerTokenFlow()
					.subdomain(getSubdomain())
					.token(getAppToken())
					.attributes(additionalAuthAttributes)
					.execute().getAccessToken();
		} catch (TokenFlowException e) {
			throw new XSUserInfoException("Error performing User Token Flow.", e);
		}
		return userToken;
	}

	private String performClientCredentialsFlow(XsuaaTokenFlows xsuaaTokenFlows,
			Map<String, String> additionalAuthAttributes) {
		String ccfToken;
		try {
			ccfToken = xsuaaTokenFlows.clientCredentialsTokenFlow()
					.subdomain(getSubdomain())
					.attributes(additionalAuthAttributes)
					.execute().getAccessToken();
		} catch (TokenFlowException e) {
			throw new XSUserInfoException("Error performing Client Credentials Flow.", e);
		}
		return ccfToken;
	}

}
