/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.springframework.util.Assert;

/**
 * An internal token exchange request capturing data by the token flow builders
 * {@link ClientCredentialsTokenFlow} and {@link UserTokenFlow}.
 */
class XsuaaTokenFlowRequest {

	private URI tokenEndpoint;
	private URI authorizeEndpoint;
	private URI keySetEndpoint;

	private String clientId;
	private String clientSecret;
	private Map<String, String> additionalAuthorizationAttributes;

	/**
	 * Creates a new token exchange request.
	 * 
	 * @param tokenEndpoint
	 *            - the endpoint URI of the XSUAA where to exchange the token.
	 */
	XsuaaTokenFlowRequest(URI tokenEndpoint, URI authorizeEndpoint, URI keySetEndpoint) {
		Assert.notNull(tokenEndpoint, "Token endpoint URI must not be null.");
		Assert.notNull(authorizeEndpoint, "Authorize endpoint URI must not be null.");
		Assert.notNull(keySetEndpoint, "Key set endpoint URI must not be null.");
		this.tokenEndpoint = tokenEndpoint;
		this.authorizeEndpoint = authorizeEndpoint;
		this.keySetEndpoint = keySetEndpoint;
	}

	/**
	 * Returns the token exchange endpoint URI. For example
	 * {@code https://<server>:<port>/uaa/oauth/token}.
	 * 
	 * @return the token exchange endpoint URI.
	 */
	URI getTokenEndpoint() {
		return this.tokenEndpoint;
	}

	/**
	 * Returns the endpoint to authorize scopes. For example
	 * {@code https://<server>:<port>/uaa/oauth/authorize}.
	 * 
	 * @return the endpoint to authorize scopes.
	 */
	URI getAuthorizeEndpoint() {
		return this.authorizeEndpoint;
	}

	/**
	 * Returns the endpoint to fetch the public key set from. For example
	 * {@code https://<server>:<port>/.well-known/jwks.json}.
	 * 
	 * @return the endpoint to fetch the public key set from.
	 */
	URI getKeySetEndpoint() {
		return this.keySetEndpoint;
	}

	/**
	 * Returns the OAuth 2.0 client ID of the token flow request.
	 * 
	 * @return the client ID or {@code null} if not set.
	 */
	String getClientId() {
		return this.clientId;
	}

	/**
	 * Sets the OAuth 2.0 client ID for this request.
	 * 
	 * @param clientId
	 *            - the client ID.
	 */
	void setClientId(String clientId) {
		Assert.notNull(clientId, "OAuth 2.0 client ID must not be null.");
		this.clientId = clientId;
	}

	/**
	 * Returns the OAuth 2.0 client secret of the token flow request.
	 * 
	 * @return the client secret or {@code null} if not set.
	 */
	String getClientSecret() {
		return this.clientSecret;
	}

	/**
	 * Sets the OAuth 2.0 client secret of this request.
	 * 
	 * @param clientSecret
	 *            - the client secret.
	 */
	void setClientSecret(String clientSecret) {
		Assert.notNull(clientSecret, "OAuth 2.0 client secret must not be null.");
		this.clientSecret = clientSecret;
	}

	/**
	 * Returns the list of requested additional authorization attributes, or null if
	 * no additional authorization attributes have been set.
	 * 
	 * @return the list of requested additional authorization attributes, or null if
	 *         no additional authorization attributes have been set.
	 */
	Map<String, String> getAdditionalAuthorizationAttributes() {
		return additionalAuthorizationAttributes;
	}

	/**
	 * Sets the requested additional authorization attributes for this token
	 * exchange request. Applications can use this to add additional authorization
	 * attributes to the exchanged access token.
	 * 
	 * @param additionalAuthorizationAttributes
	 *            - the additional authorization attributes the exchanged token
	 *            should contain.
	 */
	void setAdditionalAuthorizationAttributes(Map<String, String> additionalAuthorizationAttributes) {
		this.additionalAuthorizationAttributes = new HashMap<>(additionalAuthorizationAttributes);
	}

	/**
	 * Checks if all necessary fields of this request have been set.
	 * 
	 * @return {@code true}, if the request has all mandatory fields set.
	 *         {@code false} otherwise.
	 */
	boolean isValid() {
		return (tokenEndpoint != null) && (clientId != null) && (clientSecret != null);
	}
}
