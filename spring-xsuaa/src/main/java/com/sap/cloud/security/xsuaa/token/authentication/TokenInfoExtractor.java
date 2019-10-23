package com.sap.cloud.security.xsuaa.token.authentication;

import com.nimbusds.jwt.JWT;

/**
 * Responsible to extract information out of the token and provide it to the
 * JwtDecoder.
 */
public interface TokenInfoExtractor {

	/**
	 * @param jwt the token.
	 * @return the public key URL of the authorization server.
	 */
	String getJku(JWT jwt);

	/**
	 * @param jwt the token.
	 * @return the extracted kid claim.
	 */
	String getKid(JWT jwt);

	/**
	 * @param jwt the token.
	 * @return the extracted UAA domain.
	 */
	String getUaaDomain(JWT jwt);
}
