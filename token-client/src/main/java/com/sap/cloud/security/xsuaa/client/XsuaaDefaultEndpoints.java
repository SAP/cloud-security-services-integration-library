/**
 * SPDX-FileCopyrightText: 2018-2021 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * 
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.util.UriUtil.expandPath;

public class XsuaaDefaultEndpoints implements OAuth2ServiceEndpointsProvider {
	private final URI baseUri;
	private static final String TOKEN_ENDPOINT = "/oauth/token";
	private static final String AUTHORIZE_ENDPOINT = "/oauth/authorize";
	private static final String KEYSET_ENDPOINT = "/token_keys";

	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaDefaultEndpoints.class);

	/**
	 * Creates a new XsuaaDefaultEndpoints.
	 *
	 * @param baseUri
	 *            - the base URI of XSUAA. Based on the base URI the tokenEndpoint,
	 *            authorize and key set URI (JWKS) will be derived.
	 */
	public XsuaaDefaultEndpoints(URI baseUri) {
		assertNotNull(baseUri, "XSUAA base URI must not be null.");
		LOGGER.debug("Xsuaa default service endpoint = {}", baseUri);
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

}
