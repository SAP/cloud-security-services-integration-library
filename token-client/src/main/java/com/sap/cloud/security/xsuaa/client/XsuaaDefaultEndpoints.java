package com.sap.cloud.security.xsuaa.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;

public class XsuaaDefaultEndpoints implements OAuth2ServiceEndpointsProvider {
	private final URI baseUri;
	private static final String TOKEN_ENDPOINT = "/oauth/token";
	private static final String AUTHORIZE_ENDPOINT = "/oauth/authorize";
	private static final String KEYSET_ENDPOINT = "/token_keys";

	/**
	 * Creates a new XsuaaRestClient.
	 *
	 * @param baseUri
	 *            - the base URI of XSUAA. Based on the base URI the tokenEndpoint,
	 *            authorize and key set URI (JWKS) will be derived.
	 */
	public XsuaaDefaultEndpoints(URI baseUri) {
		Assert.notNull(baseUri, "XSUAA base URI must not be null.");
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
		return getUriWithPathAppended(TOKEN_ENDPOINT);
	}

	@Override
	public URI getAuthorizeEndpoint() {
		return getUriWithPathAppended(AUTHORIZE_ENDPOINT);
	}

	@Override
	public URI getJwksUri() {
		return getUriWithPathAppended(KEYSET_ENDPOINT);
	}

	private URI getUriWithPathAppended(String pathToAppend) {
		try {
			String newPath = baseUri.getPath() + pathToAppend;
			return new URI(baseUri.getScheme(), baseUri.getUserInfo(), baseUri.getHost(), baseUri.getPort(),
					replaceDoubleSlashes(newPath), baseUri.getQuery(), baseUri.getFragment());
		} catch (URISyntaxException e) {
			throw new IllegalStateException(e);
		}
	}

	private String replaceDoubleSlashes(String newPath) {
		return newPath.replaceAll("//", "/");
	}
}
