package adapter.xs;

import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.GrantType;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.xsa.security.container.XSTokenRequest;
import com.sap.xsa.security.container.XSUserInfo;
import com.sap.xsa.security.container.XSUserInfoException;

import java.util.Optional;
import java.util.function.Supplier;

public class XSUserInfoAdapter implements XSUserInfo {

	static final String EXTERNAL_CONTEXT = "ext_ctx";
	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
	static final String XS_USER_ATTRIBUTES = "xs.user.attributes";
	static final String XS_SYSTEM_ATTRIBUTES = "xs.system.attributes";
	static final String HDB_NAMEDUSER_SAML = "hdb.nameduser.saml";
	static final String SERVICEINSTANCEID = "serviceinstanceid";
	static final String ZDN = "zdn";
	static final String SYSTEM = "SYSTEM";
	static final String HDB = "HDB";
	static final String ISSUER = "iss";
	static final String EXTERNAL_ATTR = "ext_attr";
	private final XsuaaToken xsuaaToken;

	public XSUserInfoAdapter(Token xsuaaToken) throws XSUserInfoException {
		if(!(xsuaaToken instanceof XsuaaToken)) {
			throw new XSUserInfoException("token needs to be an instance of XsuaaToken.");
		}
		this.xsuaaToken = (XsuaaToken) xsuaaToken;
	}

	public XSUserInfoAdapter(XsuaaToken xsuaaToken) throws XSUserInfoException {
		if(xsuaaToken == null) {
			throw new XSUserInfoException("token must not be null.");
		}
		this.xsuaaToken = xsuaaToken;
	}

	@Override
	public String getLogonName() throws XSUserInfoException {
		return getClaimValue(TokenClaims.XSUAA.USER_NAME);
	}


	@Override
	public String getGivenName() throws XSUserInfoException {
		return getClaimValue(TokenClaims.XSUAA.GIVEN_NAME);
	}

	@Override
	public String getFamilyName() throws XSUserInfoException {
		return getClaimValue(TokenClaims.XSUAA.FAMILY_NAME);
	}

	@Override
	public String getOrigin() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("getOrigin");
		return getClaimValue(TokenClaims.XSUAA.ORIGIN);
	}

	@Override
	public String getIdentityZone() throws XSUserInfoException {
		return getClaimValue(TokenClaims.XSUAA.SUBACCOUNT_ID);
	}

	@Override
	public String getSubaccountId() throws XSUserInfoException {
		return getIdentityZone();
	}

	@Override
	public String getSubdomain() throws XSUserInfoException {
		return Optional.ofNullable(getExternalAttribute(ZDN)).orElseThrow(createXSUserInfoException(ZDN));
	}

	@Override
	public String getClientId() throws XSUserInfoException {
		return getClaimValue(TokenClaims.XSUAA.CLIENT_ID);
	}

	@Override
	public String getJsonValue(String attribute) throws XSUserInfoException {
		return getClaimValue(attribute);
	}

	@Override
	public String getEmail() throws XSUserInfoException {
		return getClaimValue(TokenClaims.XSUAA.EMAIL);
	}

	//TODO
	@Override
	public String getDBToken() throws XSUserInfoException {
		return getHdbToken();
	}

	//TODO
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
			String token = null;
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
		return getAttributeFromClaimAsStringList(XS_USER_ATTRIBUTES, attributeName);
	}

	@Override
	public boolean hasAttributes() throws XSUserInfoException {
		checkNotGrantTypeClientCredentials("hasAttributes");
		if (xsuaaToken.hasClaim(EXTERNAL_CONTEXT)) {
			JsonObject extContext = xsuaaToken.getClaimAsJsonObject(EXTERNAL_CONTEXT);
			return extContext.contains(XS_USER_ATTRIBUTES) && !extContext.getJsonObject(EXTERNAL_CONTEXT).isEmpty();
		} else {
			return !xsuaaToken.getClaimAsJsonObject(XS_USER_ATTRIBUTES).isEmpty();
		}
	}

	@Override
	public String[] getSystemAttribute(String attributeName) throws XSUserInfoException {
		return getAttributeFromClaimAsStringList(XS_SYSTEM_ATTRIBUTES, attributeName);
	}

	private String[] getAttributeFromClaimAsStringList(String claimName, String attributeName) {
		return xsuaaToken.getClaimAsJsonObject(claimName).getAsList(attributeName, String.class)
				.toArray(new String[] {});
	}

	@Override
	public boolean checkScope(String scope) throws XSUserInfoException {
		return xsuaaToken.hasScope(scope);
	}

	@Override
	public boolean checkLocalScope(String scope) throws XSUserInfoException {
		return xsuaaToken.hasLocalScope(scope);
	}

	@Override
	public String getAdditionalAuthAttribute(String attributeName) throws XSUserInfoException {
		return Optional.ofNullable(getAttributeFromClaimAsString(CLAIM_ADDITIONAL_AZ_ATTR, attributeName)).orElseThrow(createXSUserInfoException(attributeName));
	}

	@Override
	public String getCloneServiceInstanceId() throws XSUserInfoException {
		return Optional.ofNullable(getExternalAttribute(SERVICEINSTANCEID)).orElseThrow(createXSUserInfoException(SERVICEINSTANCEID));
	}

	@Override
	public String getGrantType() throws XSUserInfoException {
		return Optional.ofNullable(xsuaaToken.getGrantType())
				.map(GrantType::toString)
				.orElseThrow(createXSUserInfoException(TokenClaims.XSUAA.GRANT_TYPE));
	}

	@Override
	public boolean isInForeignMode() throws XSUserInfoException {
		return false;
	}

	@Override
	public String requestTokenForClient(String clientId, String clientSecret, String uaaUrl)
			throws XSUserInfoException {
		return null;
	}

	@Override
	public String requestToken(XSTokenRequest tokenRequest) throws XSUserInfoException {
		return null;
	}

	private void checkNotGrantTypeClientCredentials(String methodName) throws XSUserInfoException {
		if (getGrantType().equals(GrantType.CLIENT_CREDENTIALS)) {
			String message = String.format("Method '%s' is not supported for grant type '%s'", methodName,
					GrantType.CLIENT_CREDENTIALS);
			throw new XSUserInfoException(message + GrantType.CLIENT_CREDENTIALS);
		}
	}

	private String getAttributeFromClaimAsString(String claimName, String attributeName) {
		return Optional.ofNullable(xsuaaToken.getClaimAsJsonObject(claimName))
				.map(claim -> claim.getAsString(attributeName)).orElse(null);
	}

	private String getExternalAttribute(String attributeName) {
		return getAttributeFromClaimAsString(EXTERNAL_ATTR, attributeName);
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


}

