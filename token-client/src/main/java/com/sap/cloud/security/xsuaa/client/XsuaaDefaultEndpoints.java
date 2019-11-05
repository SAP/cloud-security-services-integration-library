package com.sap.cloud.security.xsuaa.client;

import java.net.URI;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.util.UriUtil.getUriWithPathAppended;

public class XsuaaDefaultEndpoints implements OAuth2ServiceEndpointsProvider {
	private final URI baseUri;
	private static final String TOKEN_ENDPOINT = "/oauth/token";
	private static final String AUTHORIZE_ENDPOINT = "/oauth/authorize";
	private static final String KEYSET_ENDPOINT = "/token_keys";

	/**
	 * Creates a new XsuaaDefaultEndpoints.
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
	 * Creates a new XsuaaDefaultEndpoints.
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
		return getUriWithPathAppended(baseUri, TOKEN_ENDPOINT);
	}

	@Override
	public URI getAuthorizeEndpoint() {
		return getUriWithPathAppended(baseUri, AUTHORIZE_ENDPOINT);
	}

	@Override
	public URI getJwksUri() {
		return getUriWithPathAppended(baseUri, KEYSET_ENDPOINT);
	}

}
