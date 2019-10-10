package com.sap.cloud.security.xsuaa.client;

import java.net.URI;
import java.net.URISyntaxException;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;

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
		return getUriWithPathAppended(TOKEN_ENDPOINT, false);
	}

	@Override
	public URI getAuthorizeEndpoint() {
		return getUriWithPathAppended(AUTHORIZE_ENDPOINT, false);
	}

	@Override
	public URI getJwksUri() {
		return getUriWithPathAppended(KEYSET_ENDPOINT, false);
	}

	private URI getUriWithPathAppended(String pathToAppend, boolean useCertDomain) {
		try {
			String newPath = baseUri.getPath() + pathToAppend;
			String newHost = baseUri.getHost();
			if (useCertDomain == true && baseUri.getHost().contains(".authentication.")) {
				newHost = baseUri.getHost().replace(".authentication.", ".authentication.cert.");
			}
			return new URI(baseUri.getScheme(), baseUri.getUserInfo(), newHost, baseUri.getPort(),
					replaceDoubleSlashes(newPath), baseUri.getQuery(), baseUri.getFragment());
		} catch (URISyntaxException e) {
			throw new IllegalStateException(e);
		}
	}

	private String replaceDoubleSlashes(String newPath) {
		return newPath.replaceAll("//", "/");
	}

	public URI getDelegationTokenEndpoint() {
		return getUriWithPathAppended(DELEGATION_TOKEN_ENDPOINT, true);
	}
}
