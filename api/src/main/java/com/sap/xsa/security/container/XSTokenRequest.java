/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License, 
 * v. 2 except as noted otherwise in the LICENSE file 
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.xsa.security.container;

import java.net.URI;
import java.util.Map;

/**
 * @deprecated in favor of XsuaaTokenFlows API.
 */
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
	 * Returns the client ID, if set, that will be used to authenticate the client
	 * 
	 * @return the client ID if set
	 */
	public String getClientId();

	/**
	 * Sets the client ID to be used for authentication during the token request
	 * 
	 * @param clientId
	 *            a string, no more than 255 characters identifying a valid client
	 *            on the UAA
	 * @return this mutable object
	 */
	public XSTokenRequest setClientId(String clientId);

	/**
	 * Returns the client secret, if set, that will be used to authenticate the
	 * client
	 * 
	 * @return the client secret if set
	 */
	public String getClientSecret();

	/**
	 * Sets the client secret to be used for authentication during the token request
	 * 
	 * @param clientSecret
	 *            a string representing the password for a valid client on the UAA
	 * @return this mutable object
	 */
	public XSTokenRequest setClientSecret(String clientSecret);

	/**
	 * Returns the list of requested additional authorization attributes, or null if
	 * no additional authorization attributes have been requested.
	 * 
	 * @return the list of requested additional authorization attributes, or null if
	 *         no additional authorization attributes have been requested.
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
	 * Returns the type of the requested token
	 * 
	 * @return the type of the requested token
	 */
	public int getType();

	/**
	 * Set the requested token type
	 * 
	 * @param type
	 *            type of token request: TYPE_USER_TOKEN or
	 *            TYPE_CLIENT_CREDENTIAL_TOKEN
	 * @return this mutable object
	 */
	public XSTokenRequest setType(int type);

	/**
	 * @return the token endpoint URI, for example
	 *         http://localhost:8080/uaa/oauth/token
	 */
	public URI getTokenEndpoint();

	/**
	 * Set the token endpoint URI
	 * 
	 * @param tokenEndpoint
	 *            url of token endpoint
	 * @return this mutable object
	 */
	public XSTokenRequest setTokenEndpoint(URI tokenEndpoint);

	/**
	 * Returns the XSUAA base URI.
	 * 
	 * @return the XSUAA base URI.
	 */
	public URI getBaseURI();
}
