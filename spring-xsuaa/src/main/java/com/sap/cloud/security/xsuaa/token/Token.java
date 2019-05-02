package com.sap.cloud.security.xsuaa.token;

import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Date;

public interface Token extends UserDetails {
	String CLAIM_XS_USER_ATTRIBUTES = "xs.user.attributes";
	String CLAIM_SCOPES = "scope";
	String GRANTTYPE_CLIENTCREDENTIAL = "client_credentials";
	String CLIENT_ID = "cid";

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
	 * User name used for authentication, e.g. an email address or other identifier.
	 * A user might exist in multiple identity providers. The following information
	 * is required to to uniquely identify a user: - username: name of the user in
	 * an identity provider - origin: alias to an identity provider - subaccount id:
	 * identifier for the subaccount
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
	 * Return the user origin. The origin is an alias that refers to a user store in
	 * which the user is persisted. For example, users that are authenticated by the
	 * UAA itself with a username/password combination have their origin set to the
	 * value "uaa".
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
	 * Additional custom authentication attributes included by the OAuth client
	 * component. Note: this is data controlled by the requester of a token. Might
	 * be not trustworthy.
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
	 * Get the encoded authentication token, e.g. for token forwarding to another
	 * app.
	 * <p>
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
	 * @return requested token
	 * @throws URISyntaxException
	 *             in case of wron URLs
	 */
	String requestToken(XSTokenRequest tokenRequest) throws URISyntaxException;

	/**
	 * Returns list of scopes with appId prefix, e.g.
	 * "&lt;my-app!t123&gt;.Display".
	 *
	 * @return all scopes
	 */
	Collection<String> getScopes();

	/**
	 * Returns by default list of scopes {@link #getScopes()}.
	 *
	 * The default behavior can be adapted as part of
	 * {@link com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter} class
	 *
	 * @return all authorities such as scopes or an empty list
	 */
	@Override
	Collection<? extends GrantedAuthority> getAuthorities();

	/**
	 * Returns date of when jwt token expires.
	 *
	 * @return expiration date
	 */
	Date getExpirationDate();
}