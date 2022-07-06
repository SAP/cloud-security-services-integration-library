/**
 * SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.comp;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.AccessToken;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import org.springframework.security.core.GrantedAuthority;

import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE_ZDN;

/**
 * Decorates a {@code Token} issued by xsuaa to provide compatibility methods
 * for spring-xsuaa's {@code Token} interface.
 * 
 * @deprecated use methods exposed by the {@link Token} interface.
 */
@Deprecated
public class XsuaaTokenComp implements com.sap.cloud.security.xsuaa.token.Token {
	private final AccessToken token;

	private XsuaaTokenComp(final Token token) {
		this.token = (AccessToken) token;
	}

	/**
	 * Creates an instance.
	 *
	 * @param token
	 *            a token issued by xsuaa
	 * @deprecated use methods exposed by the {@link Token} interface.
	 */
	@Deprecated
	public static XsuaaTokenComp createInstance(final Token token) {
		if (Service.XSUAA.equals(token.getService())) {
			return new XsuaaTokenComp(token);
		}
		throw new IllegalArgumentException("The token is not issued by xsuaa service");
	}

	/**
	 * Creates an instance.
	 *
	 * @param jwtToken
	 *            the encoded access token, e.g. from the {@code Authorization}
	 *            header.
	 * @deprecated use methods exposed by the {@link Token} interface.
	 */
	@Deprecated
	public static XsuaaTokenComp createInstance(final String jwtToken) {
		Token aToken = Token.create(jwtToken);
		if (Service.XSUAA.equals(aToken.getService())) {
			return new XsuaaTokenComp(aToken);
		}
		throw new IllegalArgumentException("The token is not issued by xsuaa service");
	}

	/**
	 * Return subaccount identifier which is in most cases same like the identity
	 * zone. DO only use this for metering purposes. DO NOT longer use this method
	 * to get the unique tenant id! For that use {@link #getZoneId()}.
	 *
	 * @return the subaccount identifier.
	 * @deprecated use {@link AccessToken#getSubaccountId()} instead.
	 */
	@Deprecated
	public String getSubaccountId() {
		return token.getSubaccountId();
	}

	/**
	 * Return zone identifier which should be used as tenant discriminator (tenant
	 * id). For most of the old subaccounts this matches the id returned by
	 * {@link #getSubaccountId()}.
	 *
	 * @return the zone identifier.
	 * @deprecated use {@link Token#getZoneId()} instead.
	 */
	@Deprecated
	public String getZoneId() {
		return token.getZoneId();
	}

	/**
	 * Returns the subdomain of the calling tenant's subaccount.
	 *
	 * @return the subdomain of the tenant the JWT belongs to.
	 * @deprecated use {@link Token#getAttributeFromClaimAsString(String, String)}
	 *             instead
	 */
	@Deprecated
	public String getSubdomain() {
		return token.getAttributeFromClaimAsString(EXTERNAL_ATTRIBUTE, EXTERNAL_ATTRIBUTE_ZDN);
	}

	/**
	 * Returns the OAuth2 client identifier of the authentication token if present.
	 * Following OpenID Connect 1.0 standard specifications, client identifier is
	 * obtained from "azp" claim if present or when "azp" is not present from "aud"
	 * claim, but only in case there is one audience.
	 *
	 * @return the OAuth client ID.
	 * @deprecated use {@link Token#getClientId()} instead.
	 */
	@Deprecated
	public String getClientId() {
		return token.getClientId();
	}

	/**
	 * Returns the OAuth2.0 grant type used for retrieving / creating this token.
	 *
	 * @return the grant type
	 * @deprecated use {@link Token#getGrantType()} instead.
	 */
	@Deprecated
	public String getGrantType() {
		return token.getGrantType().toString();
	}

	/**
	 * Returns a unique user name of a user ({@code user_name} claim), using
	 * information from the JWT. For tokens that were issued as a result of a client
	 * credentials flow, the OAuth client ID will be returned in a special format.
	 * The following information is required to uniquely identify a user: <br>
	 *
	 * <ul>
	 * <li><b>user login name:</b> name of the user in an identity provider,
	 * provided by this method.
	 * <li><b>origin:</b> alias to an identity provider, see {@link #getOrigin()}.
	 * <li><b>zone id:</b> identifier for the zone, see {@link #getZoneId()}.
	 * </ul>
	 *
	 * @return unique principal name or null if it can not be determined.
	 * @deprecated use {@link Token#getClaimAsString(String)} instead.
	 */
	@Deprecated
	public String getLogonName() {
		return token.getClaimAsString("user_name");
	}

	/**
	 * Returns the given name of the user if present. Will try to find it first in
	 * the {@code ext_attr.given_name} claim before trying to find a
	 * {@code given_name} claim.
	 *
	 * @return the given name if present.
	 * @deprecated use {@link Token#getClaimAsString(String)} instead
	 */
	@Deprecated
	public String getGivenName() {
		return token.getClaimAsString(TokenClaims.GIVEN_NAME);
	}

	/**
	 * Returns the family name of the user if present. Will try to find it first in
	 * the {@code ext_attr.family_name} claim before trying to find a
	 * {@code family_name} claim.
	 *
	 * @return the family name if present.
	 * @deprecated use {@link Token#getClaimAsString(String)} instead
	 */
	@Deprecated
	public String getFamilyName() {
		return token.getClaimAsString(TokenClaims.FAMILY_NAME);
	}

	/**
	 * Returns the email address of the user, if present.
	 *
	 * @return The email address if present.
	 * @deprecated use {@link Token#getClaimAsString(String)} instead
	 */
	@Deprecated
	public String getEmail() {
		return token.getClaimAsString(TokenClaims.EMAIL);
	}

	/**
	 * Returns the user origin. The origin is an alias that refers to a user store
	 * in which the user is persisted. For example, users that are authenticated by
	 * the UAA itself with a username / password combination have their origin set
	 * to the value "uaa".
	 * <p>
	 * May be null in case this JWT was not created with OAuth 2.0 client
	 * credentials flow.
	 *
	 * @return the user origin if present.
	 * @deprecated use {@link Token#getClaimAsString(String)} instead
	 */
	@Deprecated
	public String getOrigin() {
		return token.getClaimAsString(TokenClaims.XSUAA.ORIGIN);
	}

	/**
	 * Returns the value of an attribute from the 'xs.user.attributes' claim.
	 *
	 * @param attributeName
	 *            name of the attribute inside 'xs.user.attributes'.
	 * @return the attribute values array or null if there exists no such attribute.
	 * @deprecated use
	 *             {@link Token#getAttributeFromClaimAsStringList(String, String)}
	 *             (String)} instead
	 */
	@Deprecated
	public String[] getXSUserAttribute(String attributeName) {
		List<String> claims = token.getAttributeFromClaimAsStringList(TokenClaims.XSUAA.XS_USER_ATTRIBUTES, attributeName);
		return claims.isEmpty() ? null : claims.toArray(new String[0]);
	}

	/**
	 * Additional custom authentication attributes included by the OAuth client
	 * component. Note: this is data controlled by the requester of a token. Might
	 * be not trustworthy.
	 *
	 * @param attributeName
	 *            name of the authentication attribute
	 * @return additional attribute value if present.
	 * @deprecated use {@link Token#getAttributeFromClaimAsString(String, String)}
	 *             instead
	 */
	@Deprecated
	public String getAdditionalAuthAttribute(String attributeName) {
		return token.getAttributeFromClaimAsString("az_attr", attributeName);
	}

	/**
	 * Returns the XSUAA clone instance ID, if present. This will only be set for
	 * tokens that were issued by an XSUAA with plan broker. Contains the service
	 * instance id if present.
	 *
	 * @return the XSUAA clone service instance id if present.
	 * @deprecated use {@link Token#getAttributeFromClaimAsString(String, String)}
	 *             instead
	 */
	@Deprecated
	public String getCloneServiceInstanceId() {
		return token.getAttributeFromClaimAsString(TokenClaims.XSUAA.EXTERNAL_ATTRIBUTE, "serviceinstanceid");
	}

	/**
	 * Get the encoded authentication token, e.g. for token forwarding to another
	 * app.
	 * <p>
	 * Never expose this token via log or via HTTP.
	 *
	 * @return token
	 * @deprecated use {@link Token#getTokenValue()} instead
	 */
	@Deprecated
	public String getAppToken() {
		return token.getTokenValue();
	}

	/**
	 * Returns list of scopes with appId prefix, e.g. "&lt;my-app!t123&gt;.Display".
	 *
	 * @return all scopes
	 * @deprecated use {@link Token#getClaimAsStringList(String)} instead
	 */
	@Deprecated
	public Collection<String> getScopes() {
		return token.getClaimAsStringList(TokenClaims.XSUAA.SCOPES);
	}

	/**
	 * @throws UnsupportedOperationException
	 *             in any case
	 */
	@Override
	@Deprecated
	public Collection<? extends GrantedAuthority> getAuthorities() {
		throw new UnsupportedOperationException(
				"does not support methods from org.springframework.security.core.userdetails.UserDetails interface");
	}

	/**
	 * @throws UnsupportedOperationException
	 *             in any case
	 */
	@Override
	@Deprecated
	public String getPassword() {
		throw new UnsupportedOperationException(
				"does not support methods from org.springframework.security.core.userdetails.UserDetails interface");
	}

	/**
	 * Returns the moment in time when the token is expired.
	 *
	 * @return the expiration point in time if present.
	 * @deprecated use {@link Token#getExpiration()} instead
	 */
	@Deprecated
	public Instant getExpiration() {
		return token.getExpiration();
	}

	/**
	 * Returns the moment in time when the token is expired.
	 *
	 * @return the expiration point in time if present.
	 * @deprecated use {@link Token#getExpiration()} instead
	 */
	@Deprecated
	public Date getExpirationDate() {
		return token.getExpiration() != null ? Date.from(token.getExpiration()) : null;
	}

	/**
	 * Returns the username used to authenticate the user. See
	 * {@code import org.springframework.security.core.userdetails.UserDetails#getUsername()}
	 * 
	 * @return the username
	 * @deprecated use {@link Token#getPrincipal()}{@code .getName()} instead
	 */
	@Deprecated
	public String getUsername() {
		return token.getPrincipal().getName();
	}

	@Override
	@Deprecated
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	@Deprecated
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	@Deprecated
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	@Deprecated
	public boolean isEnabled() {
		return true;
	}

	/**
	 * Returns the user name for token.
	 * 
	 * @return the user name.
	 * @deprecated use {@link Token#getPrincipal()}{@code .getName()} instead
	 */
	@Deprecated
	public String toString() {
		return getUsername();
	}
}
