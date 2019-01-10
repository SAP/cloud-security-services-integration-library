/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.xs2.security.container;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.lang.Nullable;
import org.springframework.web.client.RestTemplate;

public class XSTokenRequestImpl implements XSTokenRequest {

	@Deprecated
	public static final int TYPE_USER_TOKEN = 0;
	@Deprecated
	public static final int TYPE_CLIENT_CREDENTIALS_TOKEN = 1;

	private URI tokenEndpoint;

	private int type;
	private String clientId;
	private String clientSecret;
	private RestTemplate restTemplate;

	private Map<String, String> additionalAuthorizationAttributes;

	/**
	 * Constructs a token request
	 * 
	 * @param uaabaseUrl
	 *            - uaa base url
	 * @throws URISyntaxException when uaabaseUrl could not be parsed as URI
	 */
	public XSTokenRequestImpl(String uaabaseUrl) throws URISyntaxException {
		this.tokenEndpoint = new URI(uaabaseUrl + "/oauth/token");
	}

	/**
	 * Returns true if this object contains enough information to retrieve a token
	 * 
	 * @return true if this object contains enough information to retrieve a token
	 */
	public boolean isValid() {
		return !this.hasAnyNullValues(Arrays.asList(this.tokenEndpoint, this.clientId, this.clientSecret));
	}

	/**
	 * Returns the client ID, if set, that will be used to authenticate the client
	 * 
	 * @return the client ID if set
	 */
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Sets the client ID to be used for authentication during the token request
	 * 
	 * @param clientId
	 *            a string, no more than 255 characters identifying a valid client
	 *            on the UAA
	 * @return this mutable object
	 */
	public XSTokenRequest setClientId(String clientId) {
		this.clientId = clientId;
		return this;
	}

	/**
	 * Returns the client secret, if set, that will be used to authenticate the
	 * client
	 * 
	 * @return the client secret if set
	 */
	public String getClientSecret() {
		return this.clientSecret;
	}

	/**
	 * Sets the client secret to be used for authentication during the token request
	 * 
	 * @param clientSecret
	 *            a string representing the password for a valid client on the UAA
	 * @return this mutable object
	 */
	public XSTokenRequest setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
		return this;
	}

	/**
	 * Returns the list of requested additional authorization attributes, or null if
	 * no additional authorization attributes have been requested.
	 * 
	 * @return the list of requested additional authorization attributes, or null if
	 *         no additional authorization attributes have been requested.
	 */
	public Map<String, String> getAdditionalAuthorizationAttributes() {
		return additionalAuthorizationAttributes;
	}

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
	public XSTokenRequest setAdditionalAuthorizationAttributes(Map<String, String> additionalAuthorizationAttributes) {
		this.additionalAuthorizationAttributes = (additionalAuthorizationAttributes == null) ? null : new HashMap<>(additionalAuthorizationAttributes);
		return this;
	}

	/**
	 * Returns the type of the requested token
	 * 
	 * @return the type of the requested token
	 */
	public int getType() {
		return this.type;
	}

	/**
	 * Set the requested token type
	 * 
	 * @param type
	 *            an integer representing the grant type
	 * @return this mutable object
	 */
	public XSTokenRequest setType(int type) {
		this.type = type;
		return this;
	}

	/**
	 * @return the token endpoint URI, for example
	 *         http://localhost:8080/uaa/oauth/token
	 */
	public URI getTokenEndpoint() {
		return this.tokenEndpoint;
	}

	/**
	 * Set the token endpoint URI
	 * 
	 * @param tokenEndpoint
	 *            an URI representing the token endpoint of the UAA
	 * @return this mutable object
	 */
	public XSTokenRequest setTokenEndpoint(URI tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
		return this;
	}

	/**
	 * Returns true if the list or any item in the list is null
	 * 
	 * @param objects
	 *            a list of items to be evaluated for null references
	 * @return true if the list or any item in the list is null
	 */
	private boolean hasAnyNullValues(List<Object> objects) {
		if (Objects.isNull(objects)) {
			return true;
		}
		return objects.stream().filter(o -> Objects.isNull(o)).count() > 0;
	}

	/**
	 * Allows to overwrite the default RestTemplate
	 * 
	 * @param restTemplate
	 *            the custom restTemplate
	 */
	public void setRestTemplate(RestTemplate restTemplate) {
		this.restTemplate = restTemplate;
	}

	/**
	 * Returns the custom RestTemplate
	 *
	 * @return the custom restTemplate or null
	 */
	@Nullable
	public RestTemplate getRestTemplate() {
		return restTemplate;
	}

}
