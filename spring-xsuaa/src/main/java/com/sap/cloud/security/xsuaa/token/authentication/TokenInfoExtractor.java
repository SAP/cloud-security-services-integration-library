package com.sap.cloud.security.xsuaa.token.authentication;

import com.nimbusds.jwt.JWT;

/**
 * Responsible to extract information out of the token and provide it to the
 * JwtDecoder.
 */
public interface TokenInfoExtractor {

	String getJku(JWT jwt);

	String getKid(JWT jwt);

	String getUaaDomain(JWT jwt);
}
