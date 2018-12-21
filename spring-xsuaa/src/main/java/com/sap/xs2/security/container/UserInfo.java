package com.sap.xs2.security.container;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import com.sap.xsa.security.container.XSTokenRequest;
import com.sap.xsa.security.container.XSUserInfo;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

/**
 * Class providing access to common user related attributes extracted from the JWT token.
 *
 */
public class UserInfo implements XSUserInfo {

	private static final String USER_NAME = "user_name";
	private static final String GIVEN_NAME = "given_name";
	private static final String FAMILY_NAME = "family_name";
	private static final String EMAIL = "email";
	private static final String EXP = "exp";
	private static final String CID = "cid";
	private static final String ORIGIN = "origin";
	private static final String GRANT_TYPE = "grant_type";
	private static final String ADDITIONAL_AZ_ATTR = "az_attr";
	private static final String ZONE_ID = "zid";
	private static final String EXTERNAL_ATTR = "ext_attr";
	private static final String XS_SYSTEM_ATTRIBUTES = "xs.system.attributes";
	private static final String HDB_NAMEDUSER_SAML = "hdb.nameduser.saml";
	private static final String SERVICEINSTANCEID = "serviceinstanceid";
	private static final String ZDN = "zdn";
	private static final String SYSTEM = "SYSTEM";
	private static final String HDB = "HDB";
	private static final String ISSUER = "iss";
	public static final String XS_USER_ATTRIBUTES = "xs.user.attributes";
	public static final String SCOPE = "scope";
	public static final String GRANTTYPE_CLIENTCREDENTIAL = "client_credentials";
	public static final String GRANTTYPE_SAML2BEARER = "urn:ietf:params:oauth:grant-type:saml2-bearer";
	public static final String GRANTTYPE_PASSWORD = "password"; // NOSONAR
	public static final String GRANTTYPE_AUTHCODE = "authorization_code";
	public static final String GRANTTYPE_USERTOKEN = "user_token";
	public static final String EXTERNAL_CONTEXT = "ext_ctx";


	protected final Log logger = LogFactory.getLog(getClass());

	private String xsappname = null;
	private boolean foreignMode = false;
	private Jwt jwt;

	/**
	 * @param jwt
	 *            token
	 * @param xsappname
	 *            app name
	 */
	protected UserInfo(Jwt jwt, String xsappname) {
		this.xsappname = xsappname;
		this.jwt = jwt;
	}

	/**
	 * Get the logon name (attribute logon_name)
	 *
	 * @return user name
	 * @throws UserInfoException
	 *             if method is not supported for this grant type
	 */
	@Override
	public String getLogonName() throws UserInfoException {
		if (getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) {
			throw new UserInfoException("Method getLogonName is not supported for grant type " + GRANTTYPE_CLIENTCREDENTIAL);
		}
		return getJsonValueInternal(USER_NAME);
	}

	/**
	 * Get the given name (attribute given_name)
	 *
	 * @return name
	 * @throws UserInfoException
	 *             if method is not supported for this grant type
	 */
	@Override
	public String getGivenName() throws UserInfoException {
		if (getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) {
			throw new UserInfoException("Method getGivenName is not supported for grant type " + GRANTTYPE_CLIENTCREDENTIAL);
		}
		return getExternalAttributeWithFallback(GIVEN_NAME);
	}

	/**
	 * Get the family name (attribute family_name)
	 *
	 * @return family name
	 * @throws UserInfoException
	 *             if method is not supported for this grant type
	 */
	@Override
	public String getFamilyName() throws UserInfoException {
		if (getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) {
			throw new UserInfoException("Method getFamilyName is not supported for grant type " + GRANTTYPE_CLIENTCREDENTIAL);
		}
		return getExternalAttributeWithFallback(FAMILY_NAME);
	}

	/**
	 * Get the uaa identity zone from the token
	 *
	 * @return identity zone
	 * @throws UserInfoException
	 *             attribute not found
	 */
	public String getIdentityZone() throws UserInfoException {
		return getJsonValueInternal(ZONE_ID);
	}

	/**
	 * Get the subdomain from the token
	 *
	 * @return subdomain
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public String getSubdomain() throws UserInfoException {
		try {
			return getExternalAttribute(ZDN);
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * Get the client id from the token
	 *
	 * @return client id
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public String getClientId() throws UserInfoException {
		return getJsonValueInternal(CID);
	}

	/**
	 * Get the expriation date of the access token
	 *
	 * @return expiration date
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	public Date getExpirationDate() throws UserInfoException {
		return Date.from(jwt.getExpiresAt());
	}

	private String getJsonValueInternal(String attribute) throws UserInfoException {
		String data = jwt.getClaimAsString(attribute);
		if (data == null)
			throw new UserInfoException("Invalid user attribute " + attribute);
		return data;
	}

	/**
	 * Method to extract raw data from the JWT token
	 *
	 * @param attribute
	 *            attribute name
	 * @return attribute value
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Deprecated
	public String getJsonValue(String attribute) throws UserInfoException {
		return getJsonValueInternal(attribute);
	}

	/**
	 * Get email address property
	 *
	 * @return email address
	 * @throws UserInfoException
	 *             method is not supported for this grant typ
	 */
	@Override
	public String getEmail() throws UserInfoException {
		if (getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) {
			throw new UserInfoException("Method getEmail is not supported for grant type " + GRANTTYPE_CLIENTCREDENTIAL);
		}
		return getJsonValueInternal(EMAIL);
	}

	/**
	 * Get a token for personalizing the connection to the HANA database
	 *
	 * @return token
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Deprecated
	@Override
	public String getDBToken() throws UserInfoException {
		return getHdbToken();
	}

	/**
	 * Get a token for personalizing the connection to the HANA database
	 *
	 * @return token
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public String getHdbToken() throws UserInfoException {
		return getToken(SYSTEM, HDB);
	}

	/**
	 * Get the application token, e.g. for token forwarding to another app
	 *
	 * @return token
	 */
	@Override
	public String getAppToken() {
		return jwt.getTokenValue();
	}

	/**
	 * Get a token, e.g. for forwarding to other resource servers
	 *
	 * @param namespace
	 *            token namespace
	 * @param name
	 *            attribute name
	 * @return token
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Deprecated
	@Override
	public String getToken(String namespace, String name) throws UserInfoException {
		if (!(getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) && hasAttributes() && isInForeignMode()) {
			throw new UserInfoException("The SecurityContext has been initialized with an access token of a\n" + "foreign OAuth Client Id and/or Identity Zone. Furthermore, the\n" + "access token contains attributes. Due to the fact that we want to\n" + "restrict attribute access to the application that provided the \n" + "attributes, the getToken function does not return a valid token");
		}
		if (!namespace.equals(SYSTEM)) {
			throw new UserInfoException("Invalid namespace " + namespace);
		}
		if (name.equals(HDB)) {
			String token = null;
			if (this.jwt.getClaimAsMap(EXTERNAL_CONTEXT) != null)
				token = ((net.minidev.json.JSONObject) this.jwt.getClaimAsMap(EXTERNAL_CONTEXT)).getAsString(HDB_NAMEDUSER_SAML);
			else
				token = getJsonValueInternal(HDB_NAMEDUSER_SAML);

			return token;
		} else if (name.equals("JobScheduler")) {
			return jwt.getTokenValue();
		} else {
			throw new UserInfoException("Invalid name " + name + " for namespace " + namespace);
		}
	}

	/**
	 * Get a user attribute from the JWT token
	 *
	 * @return attribute values
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public String[] getAttribute(String attributeName) throws UserInfoException {
		if (getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) {
			throw new UserInfoException("Method getAttribute is not supported for grant type " + GRANTTYPE_CLIENTCREDENTIAL);
		}
		return getMultiValueAttributeFromExtObject(attributeName, XS_USER_ATTRIBUTES);
	}

	/**
	 * Check if the JWT token contains attributes
	 *
	 * @return true: attribute exists
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public boolean hasAttributes() throws UserInfoException {
		if (getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) {
			throw new UserInfoException("Method hasAttributes is not supported for grant type " + GRANTTYPE_CLIENTCREDENTIAL);
		}

		Map<String, Object> attributeData;
		if (this.jwt.containsClaim(EXTERNAL_CONTEXT)) {
			attributeData = (Map<String, Object>) this.jwt.getClaimAsMap(EXTERNAL_CONTEXT).get(XS_USER_ATTRIBUTES);
		} else {
			attributeData = this.jwt.getClaimAsMap(XS_USER_ATTRIBUTES);
		}
		if (attributeData == null) {
			return false;
		} else {
			for (String attributeName : attributeData.keySet())
				if (((JSONArray) attributeData.get(attributeName)).size() > 0) {
					return true;
				}
		}
		return false;
	}

	/**
	 * Get a system attribute from the JWT token
	 *
	 * @param attributeName
	 *            attribute name
	 * @return attribute values
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public String[] getSystemAttribute(String attributeName) throws UserInfoException {
		return getMultiValueAttributeFromExtObject(attributeName, XS_SYSTEM_ATTRIBUTES);
	}

	/**
	 * Check if a scope {@code <xsappname>.<local scope name>} is granted to a user
	 *
	 * @param scope
	 *            scope name
	 * @return true: has scope
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public boolean checkScope(String scope) throws UserInfoException {
		List<String> scopes = jwt.getClaimAsStringList(SCOPE);
		return scopes.contains(scope);
	}

	/**
	 * Check if a local scope is granted to a user
	 *
	 * @param scope
	 *            scope name
	 * @return true: has scope
	 * @throws UserInfoException
	 *             attribute cannot be found or read
	 */
	@Override
	public boolean checkLocalScope(String scope) throws UserInfoException {
		if (xsappname == null) {
			throw new UserInfoException("Property xsappname not found in VCAP_SERVICES, must be declared in xs-security.json");
		}
		return checkScope(xsappname + "." + scope);
	}

	// for unit test
	protected void setXSAppname(String xsappname) {
		this.xsappname = xsappname;
	}

	// for unit test
	protected void setForeignMode(boolean foreignMode) {
		this.foreignMode = foreignMode;
	}

	@Override
	public String getAdditionalAuthAttribute(String attributeName) throws UserInfoException {
		return getAttributeFromObject(attributeName, ADDITIONAL_AZ_ATTR);
	}

	@Override
	public String getCloneServiceInstanceId() throws UserInfoException {
		return getExternalAttribute(SERVICEINSTANCEID);
	}

	@Override
	public String getGrantType() throws UserInfoException {
		return getJsonValueInternal(GRANT_TYPE);
	}

	@Override
	public boolean isInForeignMode() throws UserInfoException {
		return foreignMode;
	}

	private String getExternalAttribute(String attributeName) throws UserInfoException {
		return getAttributeFromObject(attributeName, EXTERNAL_ATTR);
	}

	private String getExternalAttributeWithFallback(String attributeName) throws UserInfoException {
		try {
			return getExternalAttribute(attributeName);
		} catch (UserInfoException e) {
			return getJsonValueInternal(attributeName);
		}
	}

	private String getAttributeFromObject(String attributeName, String objectName) throws UserInfoException {
		Map<String, Object> dataMap = jwt.getClaimAsMap(objectName);
		if (dataMap == null) {
			throw new UserInfoException("Invalid value of " + objectName);
		}
		String data = (String) jwt.getClaimAsMap(objectName).get(attributeName);
		if (data == null)
			throw new UserInfoException("Invalid value of " + objectName);
		return data;
	}

	private String[] getMultiValueAttributeFromExtObject(String attributeName, String objectName) throws UserInfoException {
		String[] attributeValues = null;
		if (jwt.containsClaim(EXTERNAL_CONTEXT)) {
			JSONObject jsonExtern = (JSONObject) jwt.getClaimAsMap(EXTERNAL_CONTEXT);
			JSONObject jsonObject = (JSONObject) jsonExtern.get(objectName);
			JSONArray jsonArray = (JSONArray) jsonObject.get(attributeName);
			int length = jsonArray.size();
			attributeValues = new String[length];
			for (int i = 0; i < length; i++) {
				attributeValues[i] = (String) jsonArray.get(i);
			}
		} else {
			return getMultiValueAttributeFromObject(attributeName, objectName);
		}

		return attributeValues;
	}

	private String[] getMultiValueAttributeFromObject(String attributeName, String objectName) throws UserInfoException {
		String[] attributeValues = new String[0];
		Map<String, Object> jsonObject = jwt.getClaimAsMap(objectName);
		if (jsonObject == null) {
			throw new UserInfoException("Invalid value of " + objectName);
		}
		JSONArray jsonArray = (JSONArray) jsonObject.get(attributeName);
		if (jsonArray != null) {
			int length = jsonArray.size();
			attributeValues = new String[length];
			for (int i = 0; i < length; i++) {
				attributeValues[i] = (String) jsonArray.get(i);
			}
		} else {
			throw new UserInfoException("Invalid value of " + objectName);
		}
		return attributeValues;
	}

	@Override
	public String getSubaccountId() throws UserInfoException {
		return getIdentityZone();
	}

	@Override
	public String getOrigin() throws UserInfoException {
		if (getGrantType().equals(GRANTTYPE_CLIENTCREDENTIAL)) {
			throw new UserInfoException("Method getOrigin is not supported for grant type " + GRANTTYPE_CLIENTCREDENTIAL);
		}
		return getJsonValueInternal(ORIGIN);
	}

	@Override
	public String requestToken(XSTokenRequest tokenRequest) throws UserInfoException {
		if (!tokenRequest.isValid()) {
			throw new UserInfoException("Invalid grant type or missing parameters for requested grant type.");
		}
		// build authorities string for additional authorization attributes
		String authorities = null;
		if (tokenRequest.getAdditionalAuthorizationAttributes() != null) {
			Map<String, Object> azAttrMap = new HashMap<>();
			azAttrMap.put("az_attr", tokenRequest.getAdditionalAuthorizationAttributes());
			StringBuilder azStringBuilder = new StringBuilder();
			try {
				JSONObject.writeJSON(azAttrMap, azStringBuilder);
			} catch (IOException e) {
				throw new UserInfoException("Error creating json representation", e);
			}
			authorities = azStringBuilder.toString();
		}
		// check whether token endpoint has the correct subdomain, if not replace it with the subdomain of the token
		String tokenSubdomain = getSubdomain();
		String tokenRequestSubdomain = getSubdomain(tokenRequest.getTokenEndpoint().toString());
		if (tokenSubdomain != null && tokenRequestSubdomain != null && !tokenSubdomain.equals(tokenRequestSubdomain)) {
			tokenRequest.setTokenEndpoint(replaceSubdomain(tokenRequest.getTokenEndpoint(), tokenSubdomain));
		}
		// request the token based on the type
		switch (tokenRequest.getType()) {
		case XSTokenRequest.TYPE_USER_TOKEN:
			return requestTokenNamedUser(tokenRequest.getClientId(), tokenRequest.getClientSecret(), tokenRequest.getTokenEndpoint().toString(), authorities);
		case XSTokenRequest.TYPE_CLIENT_CREDENTIALS_TOKEN:
			return requestTokenTechnicalUser(tokenRequest, authorities);
		default:
			throw new UserInfoException("Invalid grant type.");
		}
	}

	private String requestTokenTechnicalUser(XSTokenRequest tokenRequest, String authorities) throws UserInfoException {
		// note: consistency checks (clientid, clientsecret and url) have already been executed
		// build uri for client credentials flow
		UriComponentsBuilder builder = UriComponentsBuilder.fromUri(tokenRequest.getTokenEndpoint()).queryParam("grant_type", "client_credentials");
		if (authorities != null) {
			builder.queryParam("authorities", authorities);
		}
		// build http headers
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.ACCEPT, "application/json");
		String credentials = tokenRequest.getClientId() + ":" + tokenRequest.getClientSecret();
		String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes());
		headers.add(HttpHeaders.AUTHORIZATION, "Basic " + base64Creds);
		HttpEntity<Map> entity = new HttpEntity<Map>(headers);
		// request the token
		RestTemplate rt = new RestTemplate();
		ResponseEntity<Map> responseEntity = rt.postForEntity(builder.build().encode().toUri(), entity, Map.class);
		if (responseEntity.getStatusCode() == HttpStatus.UNAUTHORIZED) {
			throw new UserInfoException("Call to /oauth/token was not successful (grant_type: client_credentials). Client credentials invalid");
		}
		if (responseEntity.getStatusCode() != HttpStatus.OK) {
			throw new UserInfoException("Call to /oauth/token was not successful (grant_type: client_credentials). HTTP status code: " + responseEntity.getStatusCode());
		}
		return responseEntity.getBody().get("access_token").toString();
	}

	private String requestTokenNamedUser(String serviceClientId, String serviceClientSecret, String serviceUaaUrl, String authorities) throws UserInfoException {
		// consistency checks
		if (serviceClientId == null || serviceClientSecret == null) {
			throw new UserInfoException("Invalid service credentials: Missing clientid/clientsecret.");
		}
		if (serviceUaaUrl == null) {
			throw new UserInfoException("Invalid service credentials: Missing url.");
		}
		if (!checkScope("uaa.user")) {
			throw new UserInfoException("JWT token does not include scope 'uaa.user'.");
		}
		// build uri for user token flow
		UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(serviceUaaUrl).queryParam("grant_type", "user_token").queryParam("response_type", "token").queryParam("client_id", serviceClientId);
		if (authorities != null) {
			builder.queryParam("authorities", authorities);
		}
		// build http headers
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.ACCEPT, "application/json");
		headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + this.jwt.getTokenValue());
		HttpEntity<Map> entity = new HttpEntity<Map>(headers);
		// request the token
		RestTemplate rt = new RestTemplate();
		ResponseEntity<Map> responseEntity = rt.postForEntity(builder.build().encode().toUri(), entity, Map.class);
		if (responseEntity.getStatusCode() == HttpStatus.UNAUTHORIZED) {
			throw new UserInfoException("Call to /oauth/token was not successful (grant_type: user_token). Bearer token invalid, requesting client does not have grant_type=user_token or no scopes were granted.");

		}
		if (responseEntity.getStatusCode() != HttpStatus.OK) {
			throw new UserInfoException("Call to /oauth/token was not successful (grant_type: user_token). HTTP status code: " + responseEntity.getStatusCode());

		}
		// build uri for refresh token flow
		builder = UriComponentsBuilder.fromHttpUrl(serviceUaaUrl).queryParam("grant_type", "refresh_token").queryParam("refresh_token", responseEntity.getBody().get("refresh_token").toString());
		// build http headers
		headers.clear();
		String credentials = serviceClientId + ":" + serviceClientSecret;
		String base64Creds = Base64.getEncoder().encodeToString(credentials.getBytes());
		headers.add(HttpHeaders.ACCEPT, "application/json");
		headers.add(HttpHeaders.AUTHORIZATION, "Basic " + base64Creds);
		entity = new HttpEntity<Map>(headers);
		// request the token
		responseEntity = rt.postForEntity(builder.build().encode().toUri(), entity, Map.class);
		if (responseEntity.getStatusCode() == HttpStatus.UNAUTHORIZED) {
			throw new UserInfoException("Call to /oauth/token was not successful (grant_type: refresh_token). Client credentials invalid");
		}
		if (responseEntity.getStatusCode() != HttpStatus.OK) {
			throw new UserInfoException("Call to /oauth/token was not successful (grant_type: refresh_token). HTTP status code: " + responseEntity.getStatusCode());
		}
		return responseEntity.getBody().get("access_token").toString();
	}

	@Deprecated
	public String requestTokenForClient(String serviceClientId, String serviceClientSecret, String serviceUaaUrl) throws UserInfoException {
		String url = serviceUaaUrl != null ? serviceUaaUrl + "/oauth/token" : null;
		return requestTokenNamedUser(serviceClientId, serviceClientSecret, url, null);
	}

	/**
	 * Get the subdomain from the given url
	 *
	 * @return
	 * @throws UserInfoException
	 */
	private String getSubdomain(String url) {
		String host = null;
		try {
			host = new URI(url).getHost();
		} catch (URISyntaxException e) {
			return null;
		}
		if (host == null || !host.contains(".")) {
			return null;
		}
		return host.split("\\.")[0];
	}

	/**
	 * Replace the subdomain in the given uri with the given subdomain
	 *
	 * @return
	 * @throws UserInfoException
	 */
	private URI replaceSubdomain(URI uri, String subdomain) {
		if (uri == null || subdomain == null || !uri.getHost().contains(".")) {
			return null;
		}
		UriComponentsBuilder builder = UriComponentsBuilder.newInstance().scheme(uri.getScheme()).host(subdomain + uri.getHost().substring(uri.getHost().indexOf("."))).port(uri.getPort()).path(uri.getPath());
		return uri.resolve(builder.build().toString());
	}

}
