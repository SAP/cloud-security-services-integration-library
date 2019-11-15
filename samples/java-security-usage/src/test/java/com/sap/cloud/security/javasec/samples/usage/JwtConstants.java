package com.sap.cloud.security.javasec.samples.usage;

public class JwtConstants {

	public static final class Algorithms {
		public static final String RS256 = "RS256";
		public static final String HS256 = "HS256";
	}

	public final class Header {
		public static final String TYPE = "typ";
		public static final String ALG = "alg";
		public static final String KID = "kid";
	}
}
