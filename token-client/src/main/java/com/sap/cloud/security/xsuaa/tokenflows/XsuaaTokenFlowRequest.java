/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.cloud.security.config.ClientIdentity;
import com.sap.xsa.security.container.XSTokenRequest;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

/**
 * An internal token exchange request capturing data by the token flow builders
 * {@link ClientCredentialsTokenFlow} and {@link UserTokenFlow}.
 */
class XsuaaTokenFlowRequest implements XSTokenRequest {

	private ClientIdentity clientIdentity;
	private String clientId;
	private String clientSecret;
	private final URI tokenServiceEndpoint;
	private String subdomain;
	private String zoneId;
	private Map<String, String> additionalAuthorizationAttributes;
	private static final String UNSUPPORTED_INTF_METHOD_INFO = "This XSTokenRequest method is no longer needed in context of new XsuaaTokenFlows API.";

	/**
	 * Creates a new token exchange request.
	 *
	 * @param tokenServiceEndpoint
	 *            - the URI of the OAuth server token endpoint.
	 */
	XsuaaTokenFlowRequest(@Nonnull URI tokenServiceEndpoint) {
		assertNotNull(tokenServiceEndpoint, "tokenServiceEndpoint is required");
		this.tokenServiceEndpoint = tokenServiceEndpoint;
	}

	@Override
	public URI getTokenEndpoint() {
		return this.tokenServiceEndpoint;
	}

	@Override
	public String getClientId() {
		return clientIdentity == null ? this.clientId : this.clientIdentity.getId();
	}

	@Override
	public XSTokenRequest setClientId(String clientId) {
		assertNotNull(clientId, "OAuth 2.0 client ID must not be null.");
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
		return clientIdentity == null ? this.clientSecret : this.clientIdentity.getSecret();
	}

	@Override
	public XSTokenRequest setClientSecret(String clientSecret) {
		assertNotNull(clientSecret, "OAuth 2.0 client secret must not be null.");
		this.clientSecret = clientSecret;
		return this;
	}

	public XSTokenRequest setClientIdentity(ClientIdentity clientIdentity) {
		assertNotNull(clientIdentity, "OAuth 2.0 client identification must not be null.");
		this.clientIdentity = clientIdentity;
		return this;
	}

	public ClientIdentity getClientIdentity() {
		return clientIdentity;
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

	/**
	 * @deprecated in favor of @link{XsuaaTokenFlows} API
	 */
	@Override
	@Deprecated
	public XSTokenRequest setType(int type) {
		throw new AssertionError(UNSUPPORTED_INTF_METHOD_INFO);
	}

	/**
	 * @deprecated in favor of @link{XsuaaTokenFlows} API
	 */
	@Override
	@Deprecated
	public int getType() {
		throw new AssertionError(UNSUPPORTED_INTF_METHOD_INFO);
	}

	/**
	 * @deprecated in favor of @link{{@link #setSubdomain} )}}
	 */
	@Override
	@Deprecated
	public XSTokenRequest setTokenEndpoint(URI tokenUri) {
		throw new AssertionError(UNSUPPORTED_INTF_METHOD_INFO);
	}

	/**
	 * Checks if all necessary fields of this request have been set.
	 *
	 * @return {@code true}, if the request has all mandatory fields set.
	 *         {@code false} otherwise.
	 */
	@Override
	public boolean isValid() {
		return (getTokenEndpoint() != null) && (clientIdentity.isValid());
	}

	/**
	 * Get the Identity Zone this request goes to by providing the subdomain
	 * (tenant).
	 *
	 * @return subdomain or null in case no subdomain is specified
	 */
	@Nullable
	public String getSubdomain() {
		return this.subdomain;
	}

	/**
	 * Set the Subdomain the token is requested for.
	 *
	 * @param subdomain
	 *            indicates what Identity Zone this request goes to by supplying a
	 *            subdomain (tenant).
	 *
	 * @return this mutable object
	 *
	 */
	public XSTokenRequest setSubdomain(String subdomain) {
		this.subdomain = subdomain;
		return this;
	}

	/**
	 * Get the Identity Zone
	 *
	 * @return zoneId or null in case zoneId is not present
	 */
	@Nullable
	public String getZoneId() {
		return zoneId;
	}

	public XSTokenRequest setZoneId(String zoneId) {
		this.zoneId = zoneId;
		return this;
	}
}
