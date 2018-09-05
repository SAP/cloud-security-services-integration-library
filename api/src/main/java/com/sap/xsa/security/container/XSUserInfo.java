package com.sap.xsa.security.container;


/**
 * API for OAuth resource servers to extract authentication and authorization
 * information from the OAuth token.
 */
public interface XSUserInfo {

	/**
	 * User name used for authentication, e.g. an email address or other
	 * identifier. A user might exist in multiple identity providers. The
	 * following information is required to to uniquely identify a user: - -
	 * 
	 * 
	 * - username: name of the user in an identity provider
	 * 
	 * - origin: alias to an identity provider
	 * 
	 * - subaccount id: identifier for the subaccount
	 * 
	 * @return user name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getLogonName() throws XSUserInfoException; 

	/**
	 * Given name of the user.
	 * 
	 * @return given name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getGivenName() throws XSUserInfoException;

	/**
	 * Familiy name of the user.
	 * 
	 * @return family name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getFamilyName() throws XSUserInfoException;

	/**
	 * Return the user origin. The origin is an alias that refers to a user store in which the user is persisted.
	 * For example, users that are authenticated by the UAA itself with a username/password combination
	 * have their origin set to the value uaa.
	 *
	 * @return user origin
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getOrigin() throws XSUserInfoException;

	/**
	 * Subaccount identifier
	 * @return
	 * @throws XSUserInfoException
	 */
	String getIdentityZone() throws XSUserInfoException;
	
	/**
	 * Subaccount identifier
	 * 
	 * @return subaccount identifier
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getSubaccountId() throws XSUserInfoException;

	/**
	 * Return the subdomain of this subaccount
	 * 
	 * @return subdomain
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getSubdomain() throws XSUserInfoException;

	/**
	 * Return the client id of the authentication token
	 * 
	 * @return client id
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getClientId() throws XSUserInfoException;

	@Deprecated
	public String getJsonValue(String attribute) throws XSUserInfoException;

	/**
	 * Return the email of the user
	 * 
	 * @return email
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getEmail() throws XSUserInfoException;

	@Deprecated // use getHdbToken
	public String getDBToken() throws XSUserInfoException;

	public String getHdbToken() throws XSUserInfoException;

	/**
	 * Return authentication token
	 * 
	 * @return authentication token
	 */
	public String getAppToken();

	@Deprecated
	public String getToken(String namespace, String name) throws XSUserInfoException;

	/**
	 * Return user attributes
	 * 
	 * @param attributeName
	 *            name of attribute
	 * @return attribute values array
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String[] getAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * Check if the authentication token contains user attributes
	 * 
	 * @return true if user attributes are available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public boolean hasAttributes() throws XSUserInfoException;

	@Deprecated
	public String[] getSystemAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * Check if a scope is present in the authentication token
	 * 
	 * @param scope
	 *            name of fully qualified scope
	 * @return true if scope is available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public boolean checkScope(String scope) throws XSUserInfoException;

	/**
	 * Check if a local scope is available in the authentication token
	 * 
	 * @param scope
	 *            name of local scope (ommitting the xsappid)
	 * @return true if local scope (scope without xsappid) is available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public boolean checkLocalScope(String scope) throws XSUserInfoException;

	/**
	 * Return additional authentication attributes included by the OAuth client
	 * component. Note: this is data controlled by the requester of a token.
	 * Might be not trustworthy.
	 * 
	 * @param attributeName
	 *            name of the authentication attribute
	 * @return addition authentication attributes
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getAdditionalAuthAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * In case of xsuaa broker plan tokens, it contains the service instance id
	 * 
	 * @return service instance id
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getCloneServiceInstanceId() throws XSUserInfoException;

	/**
	 * OAuth Grant Type used for this token
	 * 
	 * @return grant type
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getGrantType() throws XSUserInfoException;

	/**
	 * Check if a token issued for another OAuth client has been forwarded to a
	 * different client,
	 * 
	 * @return true if token was forwarded
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public boolean isInForeignMode() throws XSUserInfoException;

	@Deprecated // use requestToken
	public String requestTokenForClient(String clientId, String clientSecret, String uaaUrl) throws XSUserInfoException;

	/**
	 * Exchange a token into a token from another service instance
	 * 
	 * @param tokenRequest
	 *            request data
	 * @return requested token
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String requestToken(XSTokenRequest tokenRequest) throws XSUserInfoException;



}
