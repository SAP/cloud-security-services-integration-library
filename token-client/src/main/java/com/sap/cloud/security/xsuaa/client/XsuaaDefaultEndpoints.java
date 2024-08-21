/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import com.sap.cloud.security.config.CredentialType;
import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;

import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.util.UriUtil.expandPath;

public class XsuaaDefaultEndpoints implements OAuth2ServiceEndpointsProvider {
	private final URI baseUri;
	private final URI certUri;
	private static final String TOKEN_ENDPOINT = "/oauth/token";
	private static final String AUTHORIZE_ENDPOINT = "/oauth/authorize";
	private static final String KEYSET_ENDPOINT = "/token_keys";

	private static final Logger LOGGER = LoggerFactory.getLogger(XsuaaDefaultEndpoints.class);

	/**
	 * Creates a new XsuaaDefaultEndpoints.
	 *
	 * @param baseUri
	 * 		- the base URI of XSUAA. Based on the base URI the tokenEndpoint, authorize and key set URI (JWKS) will be
	 * 		derived.
	 * @param certUri
	 * 		- the cert URI of XSUAA. It is required in case of X.509 certificate based authentication.
	 */
	public XsuaaDefaultEndpoints(@Nonnull String baseUri, @Nullable String certUri) {
		assertNotNull(baseUri, "XSUAA base URI must not be null.");
		LOGGER.debug("Xsuaa default service endpoint: base url = {}, (cert url = {})", baseUri, certUri);
		this.baseUri = URI.create(baseUri);
		this.certUri = certUri != null ? URI.create(certUri) : null;
	}

	/**
	 * Creates a new XsuaaDefaultEndpoints.
	 *
	 * @param config
	 * 		- OAuth2ServiceConfiguration of XSUAA. Based on the credential-type from the configuration, the tokenEndpoint
	 * 		URI, authorize and key set URI (JWKS) will be derived.
	 */
	public XsuaaDefaultEndpoints(@Nonnull OAuth2ServiceConfiguration config) {
		assertNotNull(config, "OAuth2ServiceConfiguration must not be null.");
		this.baseUri = config.getUrl();
		final CredentialType credentialType = config.getCredentialType() != null ? config.getCredentialType() : CredentialType.BINDING_SECRET;
		this.certUri = switch (credentialType) {
			case X509, X509_GENERATED, X509_PROVIDED, X509_ATTESTED -> config.getCertUrl();
			case BINDING_SECRET, INSTANCE_SECRET -> null;
		};
	}

	@Override
	public URI getTokenEndpoint() {
		return expandPath(certUri != null ? certUri : baseUri, TOKEN_ENDPOINT);
	}

	@Override
	public URI getAuthorizeEndpoint() {
		return expandPath(certUri != null ? certUri : baseUri, AUTHORIZE_ENDPOINT);
	}

	@Override
	public URI getJwksUri() {
		assertNotNull(baseUri, "XsuaaDefaultEndpoints.getJwksUri() requires baseUri not to be null.");
		return expandPath(baseUri, KEYSET_ENDPOINT);
	}

}
