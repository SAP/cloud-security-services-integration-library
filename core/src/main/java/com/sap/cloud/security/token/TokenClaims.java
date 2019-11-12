package com.sap.cloud.security.token;

/**
 * Class with constants denoting Jwt claims as specified here:
 * https://tools.ietf.org/html/rfc7519#section-4
 */
public final class TokenClaims {
	private TokenClaims() {
		throw new IllegalStateException("Utility class");
	}

	public static final String ISSUER = "iss";
	public static final String EXPIRATION = "exp";
	public static final String AUDIENCE = "aud";
	public static final String NOT_BEFORE = "nbf";

	public final class XSUAA {
		private XSUAA() {}

		public static final String XS_USER_ATTRIBUTES = "xs.user.attributes";
		public static final String USER_NAME = "user_name";
		public static final String GIVEN_NAME = "given_name";
		public static final String FAMILY_NAME = "family_name";
		public static final String EMAIL = "email";
		public static final String ORIGIN = "origin";
		public static final String GRANT_TYPE = "grant_type";
		public static final String ZDN = "zdn";
		public static final String ZONE_ID = "zid";
		public static final String CLIENT_ID = "cid";
		public static final String SCOPES = "scope";
	}

	public final class IAS {
		private IAS() {}

		public static final String USER_NAME = "user_name";
		public static final String GIVEN_NAME = "first_name";
		public static final String FAMILY_NAME = "last_name";
		public static final String EMAIL = "mail";
	}
}