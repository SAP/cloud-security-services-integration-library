/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.Date;

@java.lang.SuppressWarnings("squid:S1214")
public interface Token extends UserDetails {

	/**
	 * Return subaccount identifier which is in most cases same like the identity
	 * zone. DO only use this for metering purposes. DO NOT longer use this method
	 * to get the unique tenant id! For that use {@link #getZoneId()}.
	 *
	 * @return the subaccount identifier.
	 */
	String getSubaccountId();

	/**
	 * Return zone identifier which should be used as tenant discriminator (tenant
	 * id). For most of the old subaccounts this matches the id returned by
	 * {@link #getSubaccountId()}.
	 *
	 * @return the zone identifier.
	 */
	String getZoneId();

	/**
	 * Returns the subdomain of the calling tenant's subaccount.
	 *
	 * @return the subdomain of the tenant the JWT belongs to.
	 */
	public String getSubdomain();

	/**
	 * Returns the OAuth2 client identifier of the authentication token if present.
	 * Following OpenID Connect 1.0 standard specifications, client identifier is
	 * obtained from "azp" claim if present or when "azp" is not present from "aud"
	 * claim, but only in case there is one audience.
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
	 * <p>
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
	 * <p>
	 * The default behavior can be adapted as part of
	 * {@link com.sap.cloud.security.xsuaa.token.TokenAuthenticationConverter} class
	 *
	 * @return all authorities such as scopes or an empty list
	 */
	@Override
	Collection<? extends GrantedAuthority> getAuthorities();

	/**
	 * Returns the moment in time when the token will be expired.
	 *
	 * @return the expiration point in time if present.
	 */
	@Nullable
	Instant getExpiration();

}