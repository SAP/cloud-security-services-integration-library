/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.client;

import java.net.URI;

public interface OAuth2ServiceEndpointsProvider {

	/**
	 * Returns token endpoint URI.
	 * 
	 * @return token endpoint, e.g. {@code https://oauth.server.com/oauth/token}
	 */
	URI getTokenEndpoint();

	/**
	 * Returns authorize endpoint URI.
	 * 
	 * @return authorize endpoint, e.g.
	 *         {@code https://oauth.server.com/oauth/authorize}
	 */
	URI getAuthorizeEndpoint();

	/**
	 * Returns Jwt Key Set URI (JWKS) as specified in
	 * /.well-known/openid-configuration.
	 *
	 * @return jwks_uri , e.g. {@code https://oauth.server.com/token_keys}
	 */
	URI getJwksUri();
}
