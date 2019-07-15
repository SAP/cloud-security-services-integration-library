package com.sap.cloud.security.xsuaa.token;

/**
 * Class with public constants denoting custom XSUAA Jwt claims.
 */
public final class TokenClaims {
	private TokenClaims() {
		throw new IllegalStateException("Utility class");
	}

	public static final String CLAIM_XS_USER_ATTRIBUTES = "xs.user.attributes";
	public static final String CLAIM_SCOPES = "scope";
	public static final String CLAIM_CLIENT_ID = "cid";
	public static final String CLAIM_USER_NAME = "user_name";
	public static final String CLAIM_GIVEN_NAME = "given_name";
	public static final String CLAIM_FAMILY_NAME = "family_name";
	public static final String CLAIM_EMAIL = "email";
	public static final String CLAIM_ORIGIN = "origin";
	public static final String CLAIM_GRANT_TYPE = "grant_type";
	public static final String CLAIM_ZDN = "zdn";
	public static final String CLAIM_ZONE_ID = "zid";
	public static final String CLAIM_ISSUER = "iss";
	public static final String CLAIM_JKU = "jku";
	public static final String CLAIM_KID = "kid";
	public static final String CLAIM_ADDITIONAL_AZ_ATTR = "az_attr";
}
