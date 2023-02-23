/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.xsa.security.container;

import java.net.URI;
import java.util.Map;

/**
 * Represents a token exchange request.
 * 
 * deprecated with version 2.4.0 in favor of the new SAP Java Client library.
 * Limitation: does not support mtls-based communication to XSUAA identity
 * provider and will be removed with version 3.0.0.
 */
@java.lang.SuppressWarnings("squid:S1214")
public interface XSTokenRequest {

	public static final int TYPE_USER_TOKEN = 0;
	public static final int TYPE_CLIENT_CREDENTIALS_TOKEN = 1;

	/**
	 * Returns true if this object contains enough information to retrieve a token
	 *
	 * @return true if this object contains enough information to retrieve a token
	 */
	public boolean isValid();

	/**
	 * Returns the OAuth 2.0 client ID, if set, that will be used to authenticate
	 * the client
	 *
	 * @return the client ID or {@code null} if not set.
	 */
	public String getClientId();

	/**
	 * Sets the OAuth 2.0 client ID to be used for authentication during the token
	 * request
	 *
	 * @param clientId
	 *            a string, no more than 255 characters identifying a valid client
	 *            on the UAA
	 * @return this mutable object
	 */
	public XSTokenRequest setClientId(String clientId);

	/**
	 * Returns the OAuth 2.0 client secret, if set, that will be used to
	 * authenticate the client
	 *
	 * @return the client secret or {@code null} if not set.
	 */
	public String getClientSecret();

	/**
	 * Sets the OAuth 2.0 client secret to be used for authentication during the
	 * token request
	 *
	 * @param clientSecret
	 *            a string representing the password for a valid client on the UAA
	 * @return this mutable object
	 */
	public XSTokenRequest setClientSecret(String clientSecret);

	/**
	 * Returns the list of requested additional authorization attributes, or null if
	 * no additional authorization attributes have been set.
	 *
	 * @return the list of requested additional authorization attributes, or null if
	 *         no additional authorization attributes have been set.
	 */
	public Map<String, String> getAdditionalAuthorizationAttributes();

	/**
	 * Sets the requested additional authorization attributes list for this token
	 * request. Use this if you would like to add additional authorization
	 * attributes to the access token
	 *
	 * @param additionalAuthorizationAttributes
	 *            a set of strings representing requested additional authorization
	 *            attributes
	 * @return this mutable object
	 */
	public XSTokenRequest setAdditionalAuthorizationAttributes(Map<String, String> additionalAuthorizationAttributes);


	/**
	 * Returns the token exchange endpoint URI. For example
	 * {@code https://<server>:<port>/oauth/token}.
	 *
	 * @return the token exchange endpoint URI.
	 */
	public URI getTokenEndpoint();

}
