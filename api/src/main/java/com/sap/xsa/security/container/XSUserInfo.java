/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.xsa.security.container;

/**
 * API for OAuth resource servers to extract authentication and authorization
 * information from the OAuth token.
 *
 * deprecated with version 2.4.0 in favor of the new SAP Java Client library.
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
	 *             {@code token.getClaimAsString(TokenClaims.USER_NAME)} from the
	 *             {@code com.sap.cloud.security.token} package or with
	 *             {@code token.getPrincipal()}.
	 * @return user name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	String getLogonName() throws XSUserInfoException;

	/**
	 * Given name of the user.
	 *
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.GIVEN_NAME)} from the
	 *             {@code com.sap.cloud.security.token} package. Only if it is not
	 *             an external attribute.
	 * @return given name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	String getGivenName() throws XSUserInfoException;

	/**
	 * Familiy name of the user.
	 *
	 * @deprecated Can be replaced with
	 *             {@code token.getClaimAsString(TokenClaims.FAMILY_NAME)} from the
	 *             {@code com.sap.cloud.security.token} package. Only if it is not
	 *             an external attribute.
	 * @return family name
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	String getFamilyName() throws XSUserInfoException;

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
	String getOrigin() throws XSUserInfoException;

	/**
	 * Return identity zone which is in most cases same like the subaccount
	 * identifier.
	 * 
	 * @deprecated Have to be replaced with {@link #getZoneId()} or
	 *             {@link #getSubaccountId()}.
	 * @return identity zone
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	@Deprecated
	String getIdentityZone() throws XSUserInfoException;

	/**
	 * Return subaccount identifier.
	 *
	 * DO only use this for metering purposes. DO NOT longer use this method to get
	 * the unique tenant id! For that use {@link #getZoneId()}.
	 *
	 * @return subaccount identifier
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	String getSubaccountId() throws XSUserInfoException;

	/**
	 * Return zone identifier which should be used as tenant discriminator (tenant
	 * id). For most of the old subaccounts this matches the id returned by
	 * {@link #getSubaccountId()}.
	 *
	 * @deprecated Can be replaced with {@code token.getZoneId()} from the
	 *             {@code com.sap.cloud.security.token} package.
	 * @return zone identifier
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	String getZoneId() throws XSUserInfoException;

	/**
	 * Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package. Also available on tokens
	 * of type {@code XsuaaToken} from java-security.
	 *
	 * @return the subdomain
	 * @throws XSUserInfoException
	 *             if subdomain is not available in the authentication token
	 */
	String getSubdomain() throws XSUserInfoException;

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
	String getClientId() throws XSUserInfoException;

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
	String getJsonValue(String attribute) throws XSUserInfoException;

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
	String getEmail() throws XSUserInfoException;

	/**
	 * @deprecated use {@link #getHdbToken()} instead.
	 * @return the hana database token
	 * @throws XSUserInfoException
	 *             if db token is not available in the authentication token
	 */
	@Deprecated
	String getDBToken() throws XSUserInfoException;

	/**
	 * Still Supported via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 *
	 * @return the hana database token
	 * @throws XSUserInfoException
	 *             if db token is not available in the authentication token
	 */
	String getHdbToken() throws XSUserInfoException;

	/**
	 * Return authentication token
	 *
	 * @deprecated Can be replaced with {@code token.getAccessToken()} from the
	 *             {@code com.sap.cloud.security.token} package.
	 * @return authentication token
	 */
	String getAppToken();

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
	 *
	 * @deprecated use {@link #getHdbToken()} instead.
	 */
	@Deprecated
	String getToken(String namespace, String name) throws XSUserInfoException;

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
	String[] getAttribute(String attributeName) throws XSUserInfoException;

	/**
	 * Check if the authentication token contains user attributes. Still Supported
	 * via {@code XSUserInfoAdapter} from the
	 * {@code com.sap.cloud.security.adapter.xs} package.
	 *
	 * @return true if user attributes are available
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	boolean hasAttributes() throws XSUserInfoException;

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
	String[] getSystemAttribute(String attributeName) throws XSUserInfoException;

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
	boolean checkScope(String scope) throws XSUserInfoException;

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
	boolean checkLocalScope(String scope) throws XSUserInfoException;

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
	String getAdditionalAuthAttribute(String attributeName) throws XSUserInfoException;

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
	String getCloneServiceInstanceId() throws XSUserInfoException;

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
	String getGrantType() throws XSUserInfoException;

	/**
	 * Check if a token issued for another OAuth client has been forwarded to a
	 * different client,
	 *
	 *
	 * @return true if token was forwarded
	 * @throws XSUserInfoException
	 *             if attribute is not available in the authentication token
	 */
	boolean isInForeignMode() throws XSUserInfoException;

	/**
	 * Performs a client credentials token flow.
	 *
	 * @param clientId
	 *            client id
	 * @param clientSecret
	 *            client secret
	 * @param uaaUrl
	 *            the uaa url
	 * @return the token
	 *
	 * @deprecated can be replaced with token flows from the token-client library.
	 *             Does not support mtls-based communication to XSUAA identity
	 *             provider and will be removed with version 3.0.0.
	 *
	 * @throws XSUserInfoException
	 *             if an error occurs during token request
	 */
	@Deprecated
	String requestTokenForClient(String clientId, String clientSecret, String uaaUrl) throws XSUserInfoException;

	/**
	 * Performs a user token flow.
	 *
	 * @param clientId
	 *            client id
	 * @param clientSecret
	 *            client secret
	 * @param uaaUrl
	 *            the uaa url
	 * @return the token
	 * @deprecated can be replaced with token flows from the token-client library.
	 *             Does not support mtls-based communication to XSUAA identity
	 *             provider and will be removed with version 3.0.0.
	 *
	 * @throws XSUserInfoException
	 *             if an error occurs during token request
	 */
	@Deprecated
	String requestTokenForUser(String clientId, String clientSecret, String uaaUrl) throws XSUserInfoException;

	/**
	 * Exchange a token into a token from another service instance
	 *
	 * @param tokenRequest
	 *            request data
	 * @deprecated can be replaced with token flows from the token-client library.
	 *             Does not support mtls-based communication to XSUAA identity
	 *             provider and will be removed with version 3.0.0.
	 * @return requested token
	 * @throws XSUserInfoException
	 *             if an error occurs during token exchange
	 */
	@Deprecated
	String requestToken(XSTokenRequest tokenRequest) throws XSUserInfoException;

}
