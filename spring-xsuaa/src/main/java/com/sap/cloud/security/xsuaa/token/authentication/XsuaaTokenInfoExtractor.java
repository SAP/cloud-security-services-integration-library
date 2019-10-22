package com.sap.cloud.security.xsuaa.token.authentication;

import com.nimbusds.jwt.JWT;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_JKU;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_KID;

class XsuaaTokenInfoExtractor implements  TokenInfoExtractor {

	private final String uaaDomain;

	XsuaaTokenInfoExtractor(String uaaDomain) {
		this.uaaDomain = uaaDomain;
	}

	@Override
	public String getJku(JWT jwt) {
		return headerValueOrNull(jwt, CLAIM_JKU);
	}

	@Override
	public String getKid(JWT jwt) {
		return headerValueOrNull(jwt, CLAIM_KID);
	}

	@Override
	public String getUaaDomain(JWT jwt) {
		return uaaDomain;
	}

	private String headerValueOrNull(JWT jwt, String key) {
		return (String) jwt.getHeader().toJSONObject().getOrDefault(key, null);
	}
}
