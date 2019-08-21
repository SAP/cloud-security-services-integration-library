package com.sap.cloud.security.xsuaa.client;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriComponentsBuilder;

public class XsuaaDefaultEndpoints implements OAuth2ServiceEndpointsProvider {
	private final URI baseUri;
	private final static String TOKEN_ENDPOINT = "/oauth/token";
	private final static String AUTHORIZE_ENDPOINT = "/oauth/authorize";
	private final static String KEYSET_ENDPOINT = "/token_keys";
	private static Logger logger = LoggerFactory.getLogger(XsuaaDefaultEndpoints.class);

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
		Assert.notNull(baseUri, "XSUAA base URI must not be null.");
		this.baseUri = URI.create(baseUri);
	}

	@Override
	public URI getTokenEndpoint() {
		return UriComponentsBuilder.fromUri(baseUri).path(TOKEN_ENDPOINT).build().toUri();
	}

	@Override
	public URI getAuthorizeEndpoint() {
		return UriComponentsBuilder.fromUri(baseUri).path(AUTHORIZE_ENDPOINT).build().toUri();
	}

	@Override
	public URI getJwksUri() {
		return UriComponentsBuilder.fromUri(baseUri).path(KEYSET_ENDPOINT).build().toUri();
	}

	/**
	 * Utility method that replaces the subdomain of the URI with the given
	 * subdomain.
	 *
	 * @param uri
	 *            the URI to be replaced.
	 * @param subdomain
	 *            of the tenant.
	 * @return the URI with the replaced subdomain or the passed URI in case a
	 *         replacement was not possible.
	 */
	static public URI replaceSubdomain(@NonNull URI uri, @Nullable String subdomain) {
		Assert.notNull(uri, "the uri parameter must not be null");
		if (StringUtils.hasText(subdomain) && uri.getHost().contains(".")) {
			UriBuilder builder = UriComponentsBuilder.newInstance().scheme(uri.getScheme())
					.host(subdomain + uri.getHost().substring(uri.getHost().indexOf("."))).port(uri.getPort())
					.path(uri.getPath());
			return uri.resolve(builder.build());
		}
		logger.warn("the subdomain of the URI '{}' is not replaced by subdomain '{}'", uri, subdomain);
		return uri;
	}
}
