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

import com.sap.cloud.security.xsuaa.UaaRestClient;
import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.util.Assert;

/**
 * An internal token exchange request capturing data by the token flow builders
 * {@link ClientCredentialsTokenFlow} and {@link UserTokenFlow}.
 */
class XsuaaTokenFlowRequest implements XSTokenRequest {

	private UaaRestClient restClient;
	private String clientId;
	private String clientSecret;
	private Map<String, String> additionalAuthorizationAttributes;

	/**
	 * Creates a new token exchange request.
	 * 
	 * @param restClient
	 *            - contains the endpoint URIs of the XSUAA where to exchange the token.
	 */
	XsuaaTokenFlowRequest(UaaRestClient restClient) {
		Assert.notNull(restClient.getTokenEndpoint(), "Token endpoint URI must not be null.");
		Assert.notNull(restClient.getAuthorizeEndpoint(), "Authorize endpoint URI must not be null.");
		Assert.notNull(restClient.getJwksUri(), "Key set endpoint URI must not be null.");

		this.restClient = restClient;
	}

	@Override
	public URI getTokenEndpoint() {
		return this.restClient.getTokenEndpoint();
	}

	/**
	 * Returns the endpoint to authorize scopes. For example
	 * {@code https://<server>:<port>/uaa/oauth/authorize}.
	 *
	 * @return the endpoint to authorize scopes.
	 */
	URI getAuthorizeEndpoint() {
		return this.restClient.getAuthorizeEndpoint();
	}

	/**
	 * Returns the endpoint to fetch the public key set from. For example
	 * {@code https://<server>:<port>/.well-known/jwks.json}.
	 *
	 * @return the endpoint to fetch the public key set from.
	 */
	URI getKeySetEndpoint() {
		return this.restClient.getJwksUri();
	}

	@Override
	public String getClientId() {
		return this.clientId;
	}

	public XSTokenRequest setClientId(String clientId) {
		Assert.notNull(clientId, "OAuth 2.0 client ID must not be null.");
		this.clientId = clientId;
		return this;
	}

	/**
	 * Returns the OAuth 2.0 client secret of the token flow request.
	 *
	 * @return the client secret or {@code null} if not set.
	 */
	@Override
	public String getClientSecret() {
		return this.clientSecret;
	}

	public XSTokenRequest setClientSecret(String clientSecret) {
		Assert.notNull(clientSecret, "OAuth 2.0 client secret must not be null.");
		this.clientSecret = clientSecret;
		return this;
	}

	@Override
	public Map<String, String> getAdditionalAuthorizationAttributes() {
		return additionalAuthorizationAttributes;
	}

	@Override
	public XSTokenRequest setAdditionalAuthorizationAttributes(Map<String, String> additionalAuthorizationAttributes) {
		this.additionalAuthorizationAttributes = new HashMap<>(additionalAuthorizationAttributes);
		return this;
	}

	@Override
	// TODO delete?
	public URI getBaseURI() {
		throw new AssertionError("This method is no longer needed in context of new XsuaaTokenFlows API.");
	}

	@Override
	public XSTokenRequest setType(int type) {
		throw new AssertionError("This method is no longer needed in context of new XsuaaTokenFlows API.");
	}

	@Override
	public int getType() {
		throw new AssertionError("This method is no longer needed in context of new XsuaaTokenFlows API.");
	}

	@Override
	public XSTokenRequest setTokenEndpoint(URI tokenUri) {
		throw new AssertionError("This method is no longer needed in context of new XsuaaTokenFlows API.");
	}

	/**
	 * Checks if all necessary fields of this request have been set.
	 *
	 * @return {@code true}, if the request has all mandatory fields set.
	 *         {@code false} otherwise.
	 */
	@Override
	public boolean isValid() {
		return (getTokenEndpoint() != null) && (clientId != null) && (clientSecret != null);
	}
}
