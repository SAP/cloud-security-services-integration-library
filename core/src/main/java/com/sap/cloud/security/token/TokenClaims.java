package com.sap.cloud.security.token;

/**
 * Class with public constants denoting custom XSUAA Jwt claims.
 */
public final class TokenClaims {
	private TokenClaims() {
		throw new IllegalStateException("Utility class");
	}


	public static final String SCOPES = "scope";
	public static final String ISSUER = "iss";
	public static final String EXPIRATION = "exp";
	public static final String AUDIENCE = "aud";

	public final class XSUAA {
		public static final String XS_USER_ATTRIBUTES = "xs.user.attributes";
		public static final String USER_NAME = "user_name";
		public static final String GIVEN_NAME = "given_name";
		public static final String FAMILY_NAME = "family_name";
		public static final String EMAIL = "email";
		public static final String ORIGIN = "origin";
		public static final String GRANT_TYPE = "grant_type";
		public static final String ZDN = "zdn";
		public static final String ZONE_ID = "zid";
		public static final String JKU = "jku";
		public static final String KID = "kid";
		public static final String CLIENT_ID = "cid";
	}

	public final class IAS {
		public static final String USER_NAME = "user_name";
		public static final String GIVEN_NAME = "first_name";
		public static final String FAMILY_NAME = "last_name";
		public static final String EMAIL = "mail";
		public static final String ORIGIN = "origin";
		public static final String GRANT_TYPE = "grant_type";
		public static final String ZDN = "zdn";
		public static final String ZONE_ID = "zid";

		public static final String JKU = "jku";
		public static final String KID = "kid";
	}

	public static final String NOT_BEFORE = "nbf"; // TODO remove
}