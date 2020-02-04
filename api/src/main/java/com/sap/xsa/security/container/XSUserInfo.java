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
 * deprecated with version 2.4.0 in favor of the new SAP Java Container library.
 */
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
	 *             {@code token.getClaimAsString(TokenClaims.USER_NAME)} from
	 *             the {@code com.sap.cloud.security.token} package or with
	 *             {@code token.getPrincipal()}.
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
	 *             {@code token.getClaimAsString(TokenClaims.GIVEN_NAME)} from
	 *             the {@code com.sap.cloud.security.token} package. Only if it is
	 *             not an external attribute.
	 * @return given name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getGivenName() throws XSUserInfoException;

	/**
	 * Familiy name of the user.
	 *
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.FAMILY_NAME)}
	 *             from the {@code com.sap.cloud.security.token} package. Only if it
	 *             is not an external attribute.
	 * @return family name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
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
	 * Return identity zone which is the same like the subaccount id (tenant id).
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
	 * Return subaccount identifier which is the same like the identity zone (tenant
	 * id).
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
	 * Still Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 * 
	 * @return the subdomain
	 * @throws XSUserInfoException
	 *             if subdomain is not available in the authentication token
	 */
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
	 * @param attribute
	 *            the name of the JSON property
	 * @return value of attribute
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getJsonValue(String attribute) throws XSUserInfoException;

	/**
	 * Return the email of the user
	 * 
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.EMAIL)} from the
	 *             {@code com.sap.cloud.security.token} package.
	 * 
	 * @return email
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public String getEmail() throws XSUserInfoException;

	/**
	 * @deprecated use {@link #getHdbToken()} instead.
	 * @return the hana database token
	 * @throws XSUserInfoException
	 *             if db token is not available in the authentication token
	 */
	@Deprecated // use getHdbToken
	public String getDBToken() throws XSUserInfoException;

	/**
	 * Still Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 *
	 * @return the hana database token
	 * @throws XSUserInfoException
	 *             if db token is not available in the authentication token
	 */
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

	/**
	 * Still Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 *
	 * @param namespace
	 *            the namespace
	 * @param name
	 *            the name
	 * @return the token
	 * @throws XSUserInfoException
	 *             if token is not available in the authentication token
	 */
	public String getToken(String namespace, String name) throws XSUserInfoException;

	/**
	 * Return user attributes.
	 *
	 * Still Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 * 
	 * @param attributeName
	 *            name of attribute
	 * @return attribute values array
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String[] getAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * Check if the authentication token contains user attributes. Still Supported
	 * via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 *
	 * @return true if user attributes are available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public boolean hasAttributes() throws XSUserInfoException;

	/**
	 * Still Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 *
	 * @param attributeName
	 *            the name of the system attribute
	 * @return the system attribute
	 * @throws XSUserInfoException
	 *             if system attribute is not available in the authentication token
	 */
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
	 * Check if a "local" scope is available in the authentication token according
	 * to the {@code ScopeConverter}.
	 * 
	 * @param scope
	 *            name of local scope (the {@code XsuaaScopeConverter} omits the
	 *            xsappid)
	 * @deprecated can be replaced with {@code xsuaaToken.hasLocalScope(scope)} from
	 *             the {@code com.sap.cloud.security.token} package.
	 * @return true if local scope is available
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
	 * Still Supported via {@code XSUserInfoAdapter}
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
	 * Still Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 *
	 * @return service instance id
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	public String getCloneServiceInstanceId() throws XSUserInfoException;

	/**
	 * OAuth Grant Type used for this token
	 *
	 * @deprecated can be replaced with {@code token.getGrantType()} from the
	 *             {@code com.sap.cloud.security.token} package. This will give you
	 *             a {@code GrantType} enum entry on which you can call
	 *             {@code toString} to obtain the grant type as string, e.g.
	 *             "client_credentials".
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
	 * @deprecated tokens issued for a foreign OAuth Client Id and/or Identity Zone
	 *             is no longer supported here.
	 *
	 * @return true if token was forwarded
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	public boolean isInForeignMode() throws XSUserInfoException;

	/**
	 * @param clientId
	 *            client id
	 * @param clientSecret
	 *            client secret
	 * @param uaaUrl
	 *            the uaa url
	 * @return the token
	 *
	 * @deprecated can be replaced with token flows from the token-client library.
	 * @throws XSUserInfoException
	 *             if an error occurs during token request
	 */
	@Deprecated
	public String requestTokenForClient(String clientId, String clientSecret, String uaaUrl) throws XSUserInfoException;

	/**
	 * Exchange a token into a token from another service instance
	 * 
	 * @param tokenRequest
	 *            request data
	 * @deprecated can be replaced with token flows from the token-client library.
	 * @return requested token
	 * @throws XSUserInfoException
	 *             if an error occurs during token exchange
	 */
	public String requestToken(XSTokenRequest tokenRequest) throws XSUserInfoException;

}
