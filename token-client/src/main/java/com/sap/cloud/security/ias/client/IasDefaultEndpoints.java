/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.ias.client;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import java.net.URI;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.util.UriUtil.expandPath;

/**
 * IAS-specific endpoints provider. Derives the token endpoint from the IAS base URL.
 * <p>
 * Unlike XSUAA, IAS uses {@code /oauth2/token} and {@code /oauth2/certs} paths.
 */
public class IasDefaultEndpoints implements OAuth2ServiceEndpointsProvider {

	private static final String TOKEN_ENDPOINT = "/oauth2/token";
	private static final String AUTHORIZE_ENDPOINT = "/oauth2/authorize";
	private static final String KEYSET_ENDPOINT = "/oauth2/certs";

	private final URI baseUri;

	/**
	 * Creates a new IasDefaultEndpoints from a base URI string.
	 *
	 * @param baseUri
	 * 		the IAS base URI, e.g. {@code https://mytenant.accounts.ondemand.com}
	 */
	public IasDefaultEndpoints(@Nonnull String baseUri) {
		assertNotNull(baseUri, "IAS base URI must not be null.");
		this.baseUri = URI.create(baseUri.endsWith("/") ? baseUri.substring(0, baseUri.length() - 1) : baseUri);
	}

	/**
	 * Creates a new IasDefaultEndpoints from an {@link OAuth2ServiceConfiguration}.
	 *
	 * @param config
	 * 		the IAS service configuration
	 */
	public IasDefaultEndpoints(@Nonnull OAuth2ServiceConfiguration config) {
		assertNotNull(config, "OAuth2ServiceConfiguration must not be null.");
		this.baseUri = config.getUrl();
	}

	/**
	 * Creates a new IasDefaultEndpoints from a URI.
	 *
	 * @param baseUri
	 * 		the IAS base URI
	 */
	public IasDefaultEndpoints(@Nonnull URI baseUri) {
		assertNotNull(baseUri, "IAS base URI must not be null.");
		this.baseUri = baseUri;
	}

	/**
	 * Returns a new IasDefaultEndpoints with the subdomain replaced by the given subscriber subdomain.
	 *
	 * @param subscriberSubdomain
	 * 		the subscriber's subdomain to use
	 * @return new endpoints instance pointing to the subscriber's IAS tenant
	 */
	public IasDefaultEndpoints withSubdomain(@Nullable String subscriberSubdomain) {
		if (subscriberSubdomain == null || subscriberSubdomain.isBlank()) {
			return this;
		}
		String host = baseUri.getHost();
		int dotIndex = host.indexOf('.');
		if (dotIndex < 0) {
			return this;
		}
		String newHost = subscriberSubdomain + host.substring(dotIndex);
		URI subscriberUri = URI.create(baseUri.getScheme() + "://" + newHost
				+ (baseUri.getPort() > 0 ? ":" + baseUri.getPort() : ""));
		return new IasDefaultEndpoints(subscriberUri);
	}

	@Override
	public URI getTokenEndpoint() {
		return expandPath(baseUri, TOKEN_ENDPOINT);
	}

	@Override
	public URI getAuthorizeEndpoint() {
		return expandPath(baseUri, AUTHORIZE_ENDPOINT);
	}

	@Override
	public URI getJwksUri() {
		return expandPath(baseUri, KEYSET_ENDPOINT);
	}

	/**
	 * Returns the base URI of this IAS tenant.
	 *
	 * @return the base URI
	 */
	public URI getBaseUri() {
		return baseUri;
	}
}
