package com.sap.cloud.security.xsuaa.token;

import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Date;

public interface Token extends UserDetails {
	/*
	 * @deprecated use instead {@link TokenClaims.CLAIM_XS_USER_ATTRIBUTES}
	 */
	String CLAIM_XS_USER_ATTRIBUTES = "xs.user.attributes";
	/*
	 * @deprecated use instead {@link TokenClaims.CLAIM_SCOPES}
	 */
	String CLAIM_SCOPES = "scope";
	/*
	 * @deprecated use instead {@link TokenClaims.CLAIM_CLIENT_ID}
	 */
	String CLIENT_ID = "cid";

	String GRANTTYPE_CLIENTCREDENTIAL = "client_credentials";

	/**
	 * Returns the subaccount identifier, which can be used as tenant GUID.
	 *
	 * @return the subaccount identifier.
	 */
	String getSubaccountId();

	/**
	 * Returns the subdomain of the calling tenant's subaccount.
	 *
	 * @return the subdomain of the tenant the JWT belongs to.
	 */
	public String getSubdomain();

	/**
	 * Returns the OAuth client identifier of the authentication token if present.
	 *
	 * @return the OAuth client ID.
	 */
	String getClientId();

	/**
	 * Returns the OAuth2.0 grant type used for retrieving / creating this token.
	 *
	 * @return the grant type
	 */
	String getGrantType();

	/**
	 * Returns a unique user name of a user, using information from the JWT. For
	 * tokens that were issued as a result of a client credentials flow, the OAuth
	 * client ID will be returned in a special format. The following information is
	 * required to uniquely identify a user: <br>
	 *
	 * <ul>
	 * <li><b>user login name:</b> name of the user in an identity provider,
	 * provided by this method.
	 * <li><b>origin:</b> alias to an identity provider, see {@link #getOrigin()}.
	 * <li><b>subaccount id:</b> identifier for the subaccount, see
	 * {@link #getSubaccountId()}.
	 * </ul>
	 *
	 * @return unique principal name or null if it can not be determined.
	 */
	@Nullable
	String getLogonName();

	/**
	 * Returns the given name of the user if present. Will try to find it first in
	 * the {@code ext_attr.given_name} claim before trying to find a
	 * {@code given_name} claim.
	 *
	 * @return the given name if present.
	 */
	@Nullable
	String getGivenName();

	/**
	 * Returns the family name of the user if present. Will try to find it first in
	 * the {@code ext_attr.family_name} claim before trying to find a
	 * {@code family_name} claim.
	 *
	 * @return the family name if present.
	 */
	@Nullable
	String getFamilyName();

	/**
	 * Returns the email address of the user, if present.
	 *
	 * @return The email address if present.
	 */
	@Nullable
	String getEmail();

	/**
	 * Returns the user origin. The origin is an alias that refers to a user store
	 * in which the user is persisted. For example, users that are authenticated by
	 * the UAA itself with a username / password combination have their origin set
	 * to the value "uaa".
	 *
	 * May be null in case this JWT was not created with OAuth 2.0 client
	 * credentials flow.
	 *
	 * @return the user origin if present.
	 */
	@Nullable
	String getOrigin();

	/**
	 * Returns the value of an attribute from the 'xs.user.attributes' claim. Will
	 * first try to find the attribute in 'ext_ctx' claim.
	 *
	 * @param attributeName
	 *            name of the attribute inside 'ext_ctx' or 'xs.user.attributes'.
	 *
	 * @return the attribute values array or null if there exists no such attribute.
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
	 * @return additional attribute value if present.
	 */
	@Nullable
	String getAdditionalAuthAttribute(String attributeName);

	/**
	 * Returns the XSUAA clone instance ID, if present. This will only be set for
	 * tokens that were issued by an XSUAA with plan broker. Contains the service
	 * instance id if present.
	 *
	 * @return the XSUAA clone service instance id if present.
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
	 * Returns list of scopes with appId prefix, e.g. "&lt;my-app!t123&gt;.Display".
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
	 * @return expiration date if present
	 */
	@Nullable
	Date getExpirationDate();

	/**
	 * Exchange a token into a token from another service instance
	 * <p>
	 * 
	 * @deprecated in favor of the XsuaaTokenFlows API.
	 *
	 * @param tokenRequest
	 *            request data
	 * @return requested token
	 * @throws URISyntaxException
	 *             in case of wron URLs
	 */
	String requestToken(XSTokenRequest tokenRequest) throws URISyntaxException;
}