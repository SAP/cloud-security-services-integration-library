package com.sap.cloud.security.xsuaa.client;

import java.net.URI;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

import com.sap.cloud.security.xsuaa.util.UriUtil;

public class XsuaaDefaultEndpoints implements OAuth2ServiceEndpointsProvider {
	private final URI baseUri;
	private static final String TOKEN_ENDPOINT = "/oauth/token";
	private static final String AUTHORIZE_ENDPOINT = "/oauth/authorize";
	private static final String KEYSET_ENDPOINT = "/token_keys";
	private static final String DELEGATION_TOKEN_ENDPOINT = "/delegation/oauth/token";

	/**
	 * Creates a new XsuaaRestClient.
	 *
	 * @param baseUri
	 *            - the base URI of XSUAA. Based on the base URI the tokenEndpoint,
	 *            authorize and key set URI (JWKS) will be derived.
	 */
	public XsuaaDefaultEndpoints(URI baseUri) {
		assertNotNull(baseUri, "XSUAA base URI must not be null.");
		this.baseUri = baseUri;
	}

	/**
	 * Creates a new XsuaaRestClient.
	 *
	 * @param baseUri
	 *            - the base URI of XSUAA. Based on the base URI the tokenEndpoint,
	 *            authorize and key set URI (JWKS) will be derived.
	 */
	public XsuaaDefaultEndpoints(String baseUri) {
		this(URI.create(baseUri));
	}

	@Override
	public URI getTokenEndpoint() {
		return UriUtil.expandPath(baseUri, TOKEN_ENDPOINT);
	}

	@Override
	public URI getAuthorizeEndpoint() {
		return UriUtil.expandPath(baseUri, AUTHORIZE_ENDPOINT);
	}

	@Override
	public URI getJwksUri() {
		return UriUtil.expandPath(baseUri, KEYSET_ENDPOINT);
	}

	public URI getDelegationTokenEndpoint() {
		URI newUri = UriUtil.expandPath(baseUri, DELEGATION_TOKEN_ENDPOINT);
		return UriUtil.setCertDomain(newUri);
	}
}
