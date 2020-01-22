package adapter.xs;

import com.sap.cloud.security.token.GrantType;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.XsuaaToken;
import com.sap.xsa.security.container.XSTokenRequest;
import com.sap.xsa.security.container.XSUserInfo;
import com.sap.xsa.security.container.XSUserInfoException;

public class XSUserInfoAdapter implements XSUserInfo {

	static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
	static final String XS_USER_ATTRIBUTES = "xs.user.attributes";
	static final String XS_SYSTEM_ATTRIBUTES = "xs.system.attributes";
	static final String HDB_NAMEDUSER_SAML = "hdb.nameduser.saml";
	static final String SERVICEINSTANCEID = "serviceinstanceid";
	static final String ZDN = "zdn";
	static final String SYSTEM = "SYSTEM";
	static final String HDB = "HDB";
	static final String ISSUER = "iss";

	private final XsuaaToken token;

	public XSUserInfoAdapter(XsuaaToken token) {
		this.token = token;
	}

	@Override
	public String getLogonName() throws XSUserInfoException {
		return token.getClaimAsString(TokenClaims.XSUAA.USER_NAME);
	}

	@Override
	public String getGivenName() throws XSUserInfoException {
		return token.getClaimAsString(TokenClaims.XSUAA.GIVEN_NAME);
	}

	@Override
	public String getFamilyName() throws XSUserInfoException {
		return token.getClaimAsString(TokenClaims.XSUAA.FAMILY_NAME);
	}

	@Override
	public String getOrigin() throws XSUserInfoException {
		return null;
	}

	@Override
	public String getIdentityZone() throws XSUserInfoException {
		return token.getClaimAsString(TokenClaims.XSUAA.SUBACCOUNT_ID);
	}

	@Override
	public String getSubaccountId() throws XSUserInfoException {
		return null;
	}

	@Override
	public String getSubdomain() throws XSUserInfoException {
		return null;
	}

	@Override
	public String getClientId() throws XSUserInfoException {
		return token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID);
	}

	@Override
	public String getJsonValue(String attribute) throws XSUserInfoException {
		return token.getClaimAsString(attribute);
	}

	@Override
	public String getEmail() throws XSUserInfoException {
		return token.getClaimAsString(TokenClaims.XSUAA.EMAIL);
	}

	//TODO
	@Override
	public String getDBToken() throws XSUserInfoException {
		return null;
	}

	//TODO
	@Override
	public String getHdbToken() throws XSUserInfoException {
		return null;
	}

	@Override
	public String getAppToken() {
		return token.getAccessToken();
	}

	@Override
	public String getToken(String namespace, String name) throws XSUserInfoException {
		return null;
	}

	@Override
	public String[] getAttribute(String attributeName) throws XSUserInfoException {
		if (getGrantType().equals(GrantType.CLIENT_CREDENTIALS)) {
			throw new XSUserInfoException("Method getAttribute is not supported for grant type " + GrantType.CLIENT_CREDENTIALS);
		}
		return new String[] {token.getStringAttributeFromClaim(XS_USER_ATTRIBUTES, attributeName)};

	}

	@Override
	public boolean hasAttributes() throws XSUserInfoException {
		return false;
	}

	@Override
	public String[] getSystemAttribute(String attributeName) throws XSUserInfoException {
		return new String[0];
	}

	@Override
	public boolean checkScope(String scope) throws XSUserInfoException {
		return token.hasScope(scope);
	}

	@Override
	public boolean checkLocalScope(String scope) throws XSUserInfoException {
		return token.hasLocalScope(scope);
	}

	@Override
	public String getAdditionalAuthAttribute(String attributeName) throws XSUserInfoException {
		return token.getStringAttributeFromClaim(CLAIM_ADDITIONAL_AZ_ATTR, attributeName);
	}

	@Override
	public String getCloneServiceInstanceId() throws XSUserInfoException {
		return null;
	}

	@Override
	public String getGrantType() throws XSUserInfoException {
		return token.getGrantType().toString();
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
}
