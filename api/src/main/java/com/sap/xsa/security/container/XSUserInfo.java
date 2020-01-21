/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License, 
 * v. 2 except as noted otherwise in the LICENSE file 
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.xsa.security.container;

/**
 * API for OAuth resource servers to extract authentication and authorization
 * information from the OAuth token.
 *
 * @deprecated with version 2.4.0 in favor of the new SAP Java Container
 *             library.
 */
@Deprecated
public interface XSUserInfo {

	/**
	 * User name used for authentication, e.g. an email address or other identifier.
	 * A user might exist in multiple identity providers. The following information
	 * is required to to uniquely identify a user: - -
	 * 
	 * 
	 * - username: name of the user in an identity provider
	 * 
	 * - origin: alias to an identity provider
	 * 
	 * - subaccount id: identifier for the subaccount
	 *
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.USER_NAME)} from
	 *             the {@code com.sap.cloud.security.token} package.
	 * @return user name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getLogonName() throws XSUserInfoException;

	/**
	 * Given name of the user.
	 *
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.GIVEN_NAME)} from
	 *             the {@code com.sap.cloud.security.token} package.
	 *             TODO: Only if it is not an external attribute.
	 * @return given name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	// TODO: 21.01.20 If it is an external attribute, we need getStringAttributeFromClaim for that.
	public String getGivenName() throws XSUserInfoException;

	/**
	 * Familiy name of the user.
	 *
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.FAMILY_NAME)}
	 *             from the {@code com.sap.cloud.security.token} package.
	 *             TODO: Only if it is not an external attribute.
	 * @return family name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	// TODO: 21.01.20 If it is an external attribute, we need getStringAttributeFromClaim for that.
	@Deprecated
	public String getFamilyName() throws XSUserInfoException;

	/**
	 * Return the user origin. The origin is an alias that refers to a user store in
	 * which the user is persisted. For example, users that are authenticated by the
	 * UAA itself with a username/password combination have their origin set to the
	 * value uaa.
	 * 
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.ORIGIN)} from the
	 *             {@code com.sap.cloud.security.token} package.
	 * @return user origin
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getOrigin() throws XSUserInfoException;

	/**
	 * Return identity zone
	 * 
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.SUBACCOUNT_ID)}
	 *             from the {@code com.sap.cloud.security.token} package.
	 * @return identity zone
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	String getIdentityZone() throws XSUserInfoException;

	/**
	 * Return subaccount identifier
	 * 
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.SUBACCOUNT_ID)}
	 *             from the {@code com.sap.cloud.security.token} package.
	 * @return subaccount identifier
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getSubaccountId() throws XSUserInfoException;

	/**
	 * Return the subdomain of this subaccount
	 *
	 * @return subdomain
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	// TODO 21.01.20 c5295400: Cannot replaced until we have getStringAttributeFromClaim
	@Deprecated
	public String getSubdomain() throws XSUserInfoException;

	/**
	 * Return the client id of the authentication token
	 *
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.CLIENT_ID)} from
	 *             the {@code com.sap.cloud.security.token} package.
	 * @return client id
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getClientId() throws XSUserInfoException;

	/**
	 * @deprecated Can be replaced with {@code token.getClaimAsString(attribute)}
	 *             from the {@code com.sap.cloud.security.token} package.
	 */
	@Deprecated
	public String getJsonValue(String attribute) throws XSUserInfoException;

	/**
	 * Return the email of the user
	 * 
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.XSUAA.EMAIL)} from the
	 *             {@code com.sap.cloud.security.token} package.
	 * 
	 * @return email
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getEmail() throws XSUserInfoException;

	// TODO XSA?
	@Deprecated // use getHdbToken
	public String getDBToken() throws XSUserInfoException;

	// TODO XSA?
	public String getHdbToken() throws XSUserInfoException;

	/**
	 * Return authentication token
	 *
	 * @deprecated Can be replaced with {@code token.getAccessToken()} from the
	 *             {@code com.sap.cloud.security.token} package.
	 * @return authentication token
	 */
	@Deprecated
	public String getAppToken();

	// TODO XSA?
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
	// TODO 21.01.20 c5295400: Cannot replaced until we have getStringListAttributeFromClaim
	public String[] getAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * Check if the authentication token contains user attributes
	 *
	 * @return true if user attributes are available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	// TODO 14.01.20 c5295400: can this be replaced?
	public boolean hasAttributes() throws XSUserInfoException;


	// TODO XSA?
	@Deprecated
	public String[] getSystemAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * Check if a scope is present in the authentication token
	 *
	 * @param scope
	 *            name of fully qualified scope
	 * @deprecated can be replaced with {@code xsuaaToken.hasScope(scope)} from the
	 *             {@code com.sap.cloud.security.token} package.
	 * @return true if scope is available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public boolean checkScope(String scope) throws XSUserInfoException;

	/**
	 * Check if a local scope is available in the authentication token
	 * 
	 * @param scope
	 *            name of local scope (ommitting the xsappid)
	 * @deprecated can be replaced with {@code xsuaaToken.hasLocalScope(scope)} from
	 *             the {@code com.sap.cloud.security.token} package.
	 * @return true if local scope (scope without xsappid) is available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public boolean checkLocalScope(String scope) throws XSUserInfoException;

	/**
	 * Return additional authentication attributes included by the OAuth client
	 * component. Note: this is data controlled by the requester of a token. Might
	 * be not trustworthy.
	 * 
	 * @param attributeName
	 *            name of the authentication attribute
	 * @return addition authentication attributes
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	// TODO 21.01.20 c5295400: Cannot replaced until we have getStringAttributeFromClaim
	public String getAdditionalAuthAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * In case of xsuaa broker plan tokens, it contains the service instance id
	 * 
	 * @return service instance id
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	// TODO 21.01.20 c5295400: Cannot replaced until we have getStringAttributeFromClaim
	public String getCloneServiceInstanceId() throws XSUserInfoException;

	/**
	 * OAuth Grant Type used for this token
	 *
	 * @deprecated can be replaced with {@code token.getGrantType()} from the
	 *             {@code com.sap.cloud.security.token} package. This will give
	 *             you a {@code GrantType} enum entry on which you can call {@code toString}
	 *             to obtain the grant type as string, e.g. "client_credentials".
	 * @return grant type
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getGrantType() throws XSUserInfoException;

	/**
	 * Check if a token issued for another OAuth client has been forwarded to a
	 * different client,
	 * 
	 * @return true if token was forwarded
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	// TODO XSA?
	public boolean isInForeignMode() throws XSUserInfoException;

	/**
	 * @deprecated can be replaced with token flows from the token client library.
	 * @throws XSUserInfoException
	 */
	@Deprecated
	public String requestTokenForClient(String clientId, String clientSecret, String uaaUrl) throws XSUserInfoException;

	/**
	 * Exchange a token into a token from another service instance
	 * 
	 * @deprecated can be replaced with token flows from the token client library.
	 * @param tokenRequest
	 *            request data
	 * @return requested token
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String requestToken(XSTokenRequest tokenRequest) throws XSUserInfoException;

}
