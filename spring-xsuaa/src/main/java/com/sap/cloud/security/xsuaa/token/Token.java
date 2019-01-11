package com.sap.cloud.security.xsuaa.token;

import java.net.URISyntaxException;
import java.util.Collection;

import org.springframework.lang.Nullable;
import org.springframework.security.core.userdetails.UserDetails;

import com.sap.xsa.security.container.XSTokenRequest;

public interface Token extends UserDetails {
	String CLAIM_XS_USER_ATTRIBUTES = "xs.user.attributes";
	String CLAIM_SCOPES = "scope";
	String GRANTTYPE_CLIENTCREDENTIAL = "client_credentials";

	/**
	 * Subaccount identifier, which can be used as tenant guid
	 *
	 * @return subaccount identifier
	 */
	String getSubaccountId();

	/**
	 * Subdomain of this subaccount
	 *
	 * @return subdomain
	 */
	public String getSubdomain();

	/**
	 * Client identifier of the authentication token
	 *
	 * @return client id
	 */
	String getClientId();

	/**
	 * OAuth Grant Type used for this token
	 *
	 * @return grant type
	 */
	String getGrantType();

	/**
	 * User name used for authentication, e.g. an email address or other identifier. A user might exist in multiple identity providers. The following
	 * information is required to to uniquely identify a user: - username: name of the user in an identity provider - origin: alias to an identity
	 * provider - subaccount id: identifier for the subaccount
	 *
	 * @return user name
	 */
	@Nullable
	String getLogonName();

	/**
	 * Given name of the user.
	 *
	 * @return given name
	 */
	@Nullable
	String getGivenName();

	/**
	 * Family name of the user.
	 *
	 * @return family name
	 */
	@Nullable
	String getFamilyName();

	/**
	 * Email address of the user.
	 *
	 * @return email address
	 */
	@Nullable
	String getEmail();

	/**
	 * Return the user origin. The origin is an alias that refers to a user store in which the user is persisted. For example, users that are
	 * authenticated by the UAA itself with a username/password combination have their origin set to the value "uaa".
	 *
	 * @return user origin
	 */
	@Nullable
	String getOrigin();

	/**
	 * User attribute
	 *
	 * @param attributeName
	 *            name of the attribute
	 * @return attribute values array
	 */
	@Nullable
	String[] getXSUserAttribute(String attributeName);

	/**
	 * Additional custom authentication attributes included by the OAuth client component. Note: this is data controlled by the requester of a token.
	 * Might be not trustworthy.
	 *
	 * @param attributeName
	 *            name of the authentication attribute
	 * @return additional attribute value
	 */
	@Nullable
	String getAdditionalAuthAttribute(String attributeName);

	/**
	 * In case of xsuaa broker plan tokens, it contains the service instance id
	 *
	 * @return service instance id
	 */
	@Nullable
	String getCloneServiceInstanceId();

	/**
	 * Get the encoded authentication token, e.g. for token forwarding to another app.
	 *
	 * Never expose this token via log or via HTTP.
	 *
	 * @return token
	 */
	String getAppToken();

	/**
	 * Exchange a token into a token from another service instance
	 *
	 * @param tokenRequest
	 *            request data
	 * @throws URISyntaxException
	 *             in case of wron URLs
	 * @return requested token
	 */
	String requestToken(XSTokenRequest tokenRequest) throws URISyntaxException;

	/**
	 * Returns list of scopes with appId prefix, e.g. "<my-xsapp!123>.Display"
	 * 
	 * @return all scopes
	 */
	Collection<String> getScopes();
}