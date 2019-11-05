package com.sap.cloud.security.xsuaa.jwt;

import com.sap.cloud.security.xsuaa.Assertions;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

public final class Base64JwtDecoder {
	private static final Base64JwtDecoder instance = new Base64JwtDecoder();

	/**
	 * @deprecated in favor of the {@link #getInstance() method} and will become
	 *             private with version 3.0.0
	 */
	@Deprecated
	public Base64JwtDecoder() {
		// becomes private with version 3.0.0
	}

	public static Base64JwtDecoder getInstance() {
		return instance;
	}

	public DecodedJwt decode(String jwt) {
		Assertions.assertNotNull(jwt, "JWT must not be null");

		String[] parts = jwt.split(Pattern.quote("."));
		if (parts.length != 3) {
			throw new IllegalArgumentException("JWT token does not consist of 'header'.'payload'.'signature'.");
		}
		String header = base64Decode(parts[0]);
		String payload = base64Decode(parts[1]);
		String signature = parts[2];

		return new DecodedJwtImpl(jwt, header, payload, signature);
	}

	private String base64Decode(String encoded) {
		byte[] decodedBytes = Base64.getDecoder().decode(encoded);
		return new String(decodedBytes, StandardCharsets.UTF_8);
	}

	static class DecodedJwtImpl implements DecodedJwt {

		private String header;
		private String payload;
		private String signature;
		private String encodedJwt;

		DecodedJwtImpl(String encodedJwt, String header, String payload, String signature) {
			this.header = header;
			this.payload = payload;
			this.signature = signature;
			this.encodedJwt = encodedJwt;
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public String getPayload() {
			return payload;
		}

		@Override
		public String getSignature() {
			return signature;
		}

		@Override
		public String getEncodedToken() {
			return encodedJwt;
		}

	}
}
