package com.sap.cloud.security.xsuaa.tokenflows;

import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static com.sap.cloud.security.xsuaa.ObjectsUtil.assertNotNull;

/**
 * An internal token exchange request capturing data by the token flow builders
 * {@link ClientCredentialsTokenFlow} and {@link UserTokenFlow}.
 */
class XsuaaTokenFlowRequest implements XSTokenRequest {

	private String clientId;
	private URI tokenServiceEndpoint;
	private String subdomain;
	private String clientSecret;
	private Map<String, String> additionalAuthorizationAttributes;

	/**
	 * Creates a new token exchange request.
	 *
	 * @param tokenServiceEndpoint
	 *            - the URI of the OAuth server token endpoint.
	 */
	XsuaaTokenFlowRequest(@NonNull URI tokenServiceEndpoint) {
		assertNotNull(tokenServiceEndpoint, "tokenServiceEndpoint is required");
		this.tokenServiceEndpoint = tokenServiceEndpoint;
	}

	@Override
	public URI getTokenEndpoint() {
		return this.tokenServiceEndpoint;
	}

	@Override
	public String getClientId() {
		return this.clientId;
	}

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
		return this.clientSecret;
	}

	public XSTokenRequest setClientSecret(String clientSecret) {
		assertNotNull(clientSecret, "OAuth 2.0 client secret must not be null.");
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

	/**
	 * @deprecated in favor of @link{XsuaaTokenFlows} API
	 */
	@Override
	public XSTokenRequest setType(int type) {
		throw new AssertionError("This method is no longer needed in context of new XsuaaTokenFlows API.");
	}

	/**
	 * @deprecated in favor of @link{XsuaaTokenFlows} API
	 */
	@Override
	public int getType() {
		throw new AssertionError("This method is no longer needed in context of new XsuaaTokenFlows API.");
	}

	/**
	 * @deprecated in favor of @link{{@link #setSubdomain} )}}
	 */
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
}
