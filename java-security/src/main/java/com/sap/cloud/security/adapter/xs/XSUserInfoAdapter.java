package com.sap.cloud.security.adapter.xs;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.cf.CFConstants;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.json.JsonParsingException;
import com.sap.cloud.security.token.GrantType;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.xsa.security.container.XSTokenRequest;
import com.sap.xsa.security.container.XSUserInfo;
import com.sap.xsa.security.container.XSUserInfoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.util.Optional;
import java.util.function.Supplier;

import static com.sap.cloud.security.config.cf.CFConstants.XSUAA.IDENTITY_ZONE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;
import static com.sap.cloud.security.token.TokenClaims.*;

public class XSUserInfoAdapter implements XSUserInfo {

	private static final Logger LOGGER = LoggerFactory.getLogger(XSUserInfoAdapter.class);

	static final String EXTERNAL_CONTEXT = "ext_ctx";
	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
	static final String XS_USER_ATTRIBUTES = "xs.user.attributes";
	static final String XS_SYSTEM_ATTRIBUTES = "xs.system.attributes";
	static final String HDB_NAMEDUSER_SAML = "hdb.nameduser.saml";
	static final String SERVICEINSTANCEID = "serviceinstanceid";
	static final String ZDN = "zdn";
	static final String SYSTEM = "SYSTEM";
	static final String HDB = "HDB";
	private final XsuaaToken xsuaaToken;
	private OAuth2ServiceConfiguration configuration;

	public XSUserInfoAdapter(Token xsuaaToken) throws XSUserInfoException {
		if (!(xsuaaToken instanceof XsuaaToken)) {
			throw new XSUserInfoException("token needs to be an instance of XsuaaToken.");
		}
		this.xsuaaToken = (XsuaaToken) xsuaaToken;
	}

	public XSUserInfoAdapter(XsuaaToken xsuaaToken) throws XSUserInfoException {
		if (xsuaaToken == null) {
			throw new XSUserInfoException("token must not be null.");
		}
		this.xsuaaToken = xsuaaToken;
	}

	public XSUserInfoAdapter(Token xsuaaToken, OAuth2ServiceConfiguration configuration) throws XSUserInfoException {
		if (!(xsuaaToken instanceof XsuaaToken)) {
			throw new XSUserInfoException("token needs to be an instance of XsuaaToken.");
		}
		this.xsuaaToken = (XsuaaToken) xsuaaToken;
		this.configuration = configuration;
	}

	@Override
	public String getLogonName() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("getLogonName");
		return getClaimValue(USER_NAME);
	}

	@Override
	public String getGivenName() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("getGivenName");
		String externalAttributeName = getExternalAttribute(GIVEN_NAME);
		if (externalAttributeName == null) {
			return getClaimValue(GIVEN_NAME);
		} else {
			return externalAttributeName;
		}
	}

	@Override
	public String getFamilyName() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("getFamilyName");
		String externalAttributeName = getExternalAttribute(FAMILY_NAME);
		if (externalAttributeName == null) {
			return getClaimValue(FAMILY_NAME);
		} else {
			return externalAttributeName;
		}
	}

	@Override
	public String getOrigin() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("getOrigin");
		return getClaimValue(ORIGIN);
	}

	@Override
	public String getIdentityZone() throws XSUserInfoException {
		return getClaimValue(SUBACCOUNT_ID);
	}

	@Override
	public String getSubaccountId() throws XSUserInfoException {
		return getIdentityZone();
	}

	@Override
	/**
	 *  "ext_attr": {
	 *         "enhancer": "XSUAA",
	 *         "zdn": "paas-subdomain"
	 *     },
	 */
	public String getSubdomain() throws XSUserInfoException {
		return Optional.ofNullable(getExternalAttribute(ZDN)).orElseThrow(createXSUserInfoException(ZDN));
	}

	@Override
	public String getClientId() throws XSUserInfoException {
		return getClaimValue(CLIENT_ID);
	}

	@Override
	public String getJsonValue(String attribute) throws XSUserInfoException {
		return getClaimValue(attribute);
	}

	@Override
	public String getEmail() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("getEmail");
		return getClaimValue(EMAIL);
	}

	@Override
	public String getDBToken() throws XSUserInfoException {
		return getHdbToken();
	}

	@Override
	public String getHdbToken() throws XSUserInfoException {
		return getToken(SYSTEM, HDB);
	}

	@Override
	public String getAppToken() {
		return xsuaaToken.getAccessToken();
	}

	@Override
	public String getToken(String namespace, String name) throws XSUserInfoException {
		if (!(getGrantType().equals(GrantType.CLIENT_CREDENTIALS)) && hasAttributes() && isInForeignMode()) {
			throw new XSUserInfoException("The SecurityContext has been initialized with an access token of a\n"
					+ "foreign OAuth Client Id and/or Identity Zone. Furthermore, the\n"
					+ "access token contains attributes. Due to the fact that we want to\n"
					+ "restrict attribute access to the application that provided the \n"
					+ "attributes, the getToken function does not return a valid token");
		}
		if (!namespace.equals(SYSTEM)) {
			throw new XSUserInfoException("Invalid namespace " + namespace);
		}
		if (name.equals(HDB)) {
			String token;
			if (xsuaaToken.hasClaim(EXTERNAL_CONTEXT)) {
				token = getAttributeFromClaimAsString(EXTERNAL_CONTEXT, HDB_NAMEDUSER_SAML);
			} else {
				token = xsuaaToken.getClaimAsString(HDB_NAMEDUSER_SAML);
			}
			if (token == null) {
				token = xsuaaToken.getAccessToken();
			}
			return token;
		} else if (name.equals("JobScheduler")) {
			return xsuaaToken.getAccessToken();
		} else {
			throw new XSUserInfoException("Invalid name " + name + " for namespace " + namespace);
		}
	}

	@Override
	public String[] getAttribute(String attributeName) throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("getAttribute");
		return getMultiValueAttributeFromExtObject(XS_USER_ATTRIBUTES, attributeName);
	}

	@Override
	public boolean hasAttributes() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("hasAttributes");
		if (xsuaaToken.hasClaim(EXTERNAL_CONTEXT)) {
			JsonObject extContext = getClaimAsJsonObject(EXTERNAL_CONTEXT);
			return extContext.contains(XS_USER_ATTRIBUTES) && !extContext.getJsonObject(EXTERNAL_CONTEXT).isEmpty();
		} else {
			return !getClaimAsJsonObject(XS_USER_ATTRIBUTES).isEmpty();
		}
	}

	@Override
	public String[] getSystemAttribute(String attributeName) throws XSUserInfoException {
		return getMultiValueAttributeFromExtObject(XS_SYSTEM_ATTRIBUTES, attributeName);
	}

	@Override
	public boolean checkScope(String scope) throws XSUserInfoException {
		return xsuaaToken.hasScope(scope);
	}

	@Override
	public boolean checkLocalScope(String scope) throws XSUserInfoException {
		try {
			return xsuaaToken.hasLocalScope(scope);
		} catch (IllegalArgumentException e) {
			throw new XSUserInfoException(e.getMessage());
		}
	}

	@Override
	public String getAdditionalAuthAttribute(String attributeName) throws XSUserInfoException {
		return Optional.ofNullable(getAttributeFromClaimAsString(CLAIM_ADDITIONAL_AZ_ATTR, attributeName))
				.orElseThrow(createXSUserInfoException(attributeName));
	}

	@Override
	public String getCloneServiceInstanceId() throws XSUserInfoException {
		return Optional.ofNullable(getExternalAttribute(SERVICEINSTANCEID))
				.orElseThrow(createXSUserInfoException(SERVICEINSTANCEID));
	}

	@Override
	public String getGrantType() throws XSUserInfoException {
		return Optional.ofNullable(xsuaaToken.getGrantType())
				.map(GrantType::toString)
				.orElseThrow(createXSUserInfoException(GRANT_TYPE));
	}

	@Override
	/**
	 * Check if a token issued for another OAuth client has been forwarded to a
	 * different client,
	 *
	 * @return true if token was forwarded or if it cannot be determined.
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public boolean isInForeignMode()  {
		final String clientId;
		final String subdomain;
		try {
			clientId = getClientId();
			subdomain = getSubdomain();
		} catch (XSUserInfoException e) {
			LOGGER.warn("Tried to access missing attribute when checking for foreign mode", e);
			return true;
		}
		if(configuration == null) {
			LOGGER.info("No configuration provided -> falling back to foreignMode = true!");
			return true; // default provide OAuth2ServiceConfiguration via constructor argument
		}
		if(clientId.equals(configuration.getClientId()) &&
			 subdomain.equals(configuration.getProperty(IDENTITY_ZONE))) {
			return false;
		} else if (matchesTokenClientIdToBrokerCloneAppId(clientId, configuration.getProperty(CFConstants.XSUAA.APP_ID))) {
			return false;
		}
		return true;
	}

	@Override
	public String requestTokenForClient(String clientId, String clientSecret, String uaaUrl) {
		throw new UnsupportedOperationException("Not implemented.");
	}

	@Override
	public String requestToken(XSTokenRequest tokenRequest) throws XSUserInfoException {
		throw new UnsupportedOperationException("Not implemented.");
	}

	private String[] getMultiValueAttributeFromExtObject(String claimName, String attributeName)
			throws XSUserInfoException {
		JsonObject claimAsJsonObject = getClaimAsJsonObject(claimName);
		return Optional.ofNullable(claimAsJsonObject)
				.map(jsonObject -> jsonObject.getAsList(attributeName, String.class))
				.map(values -> values.toArray(new String[] {}))
				.orElseThrow(createXSUserInfoException(attributeName));
	}

	private void checkNotGrantTypeClientCredentials(String methodName) throws XSUserInfoException {
		if (GrantType.CLIENT_CREDENTIALS == xsuaaToken.getGrantType()) {
			String message = String.format("Method '%s' is not supported for grant type '%s'", methodName,
					GrantType.CLIENT_CREDENTIALS);
			throw new XSUserInfoException(message + GrantType.CLIENT_CREDENTIALS);
		}
	}

	@Nullable
	private String getAttributeFromClaimAsString(String claimName, String attributeName) throws XSUserInfoException {
		return Optional.ofNullable(getClaimAsJsonObject(claimName))
				.map(claim -> claim.getAsString(attributeName)).orElse(null);
	}

	private String getExternalAttribute(String attributeName) throws XSUserInfoException {
		return getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, attributeName);
	}

	private Supplier<XSUserInfoException> createXSUserInfoException(String attribute) {
		return () -> new XSUserInfoException("Invalid user attribute " + attribute);
	}

	private String getClaimValue(String claimname) throws XSUserInfoException {
		String value = xsuaaToken.getClaimAsString(claimname);
		if (value == null) {
			throw new XSUserInfoException("Invalid user attribute " + claimname);
		}
		return value;
	}

	@Nullable
	private JsonObject getClaimAsJsonObject(String claimName) throws XSUserInfoException {
		try {
			return xsuaaToken.getClaimAsJsonObject(claimName);
		} catch (JsonParsingException e) {
			throw createXSUserInfoException(claimName).get();
		}
	}

	private boolean matchesTokenClientIdToBrokerCloneAppId(String clientId, String appid)  {
		return appid.contains("!b") // broker plan
				&& clientId.contains("|")
				&& clientId.endsWith("|" + appid);
	}

}
