package com.sap.cloud.security.xsuaa;

import java.net.URI;

public interface UaaRestClient {

	/**
	 * Returns token endpoint URI.
	 * @return token endpoint, e.g. {@code https://oauth.server.com/oauth/token}
	 */
	URI getTokenEndpoint();

	/**
	 * Returns authorize endpoint URI.
	 * @return authorize endpoint, e.g. {@code https://oauth.server.com/oauth/authorize}
	 */
	URI getAuthorizeEndpoint();

	/**
	 * Returns Jwt Key Set URI (JWKS) as specified in /.well-known/openid-configuration.
	 * @return jwks_uri , e.g. {@code https://oauth.server.com/token_keys}
	 */
	URI getJwksUri();
}
