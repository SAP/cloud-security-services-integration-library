package com.sap.cloud.security.xsuaa.token.flows;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import com.sap.xsa.security.container.XSTokenRequest;
import org.springframework.util.Assert;

/**
 * An internal token exchange request capturing data by the token flow builders
 * {@link ClientCredentialsTokenFlow} and {@link UserTokenFlow}.
 */
class XsuaaTokenFlowRequest implements XSTokenRequest {

	private String clientId;
	private URI tokenServerEndpoint;
	private String clientSecret;
	private Map<String, String> additionalAuthorizationAttributes;

	/**
	 * Creates a new token exchange request.
	 *
	 * @param oAuth2ServerTokenEndpoint - the URI of the token endpoint.
	 */
	XsuaaTokenFlowRequest(URI oAuth2ServerTokenEndpoint) {
		this.tokenServerEndpoint = oAuth2ServerTokenEndpoint;
	}

	@Override
	public URI getTokenEndpoint() {
		return this.tokenServerEndpoint;
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
