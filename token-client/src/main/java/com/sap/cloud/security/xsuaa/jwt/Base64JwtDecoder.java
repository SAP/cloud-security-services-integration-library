package com.sap.cloud.security.xsuaa.jwt;

import com.sap.cloud.security.xsuaa.Assertions;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class Base64JwtDecoder {

	public DecodedJwt decode(String jwt) {
		Assertions.assertNotNull(jwt, "JWT must not be null");

		String[] parts = jwt.split("\\.");
		if (parts.length != 3) {
			throw new IllegalArgumentException("Failed to split JWT into exactly 3 parts");
		}
		String header = base64Decode(parts[0]);
		String payload = base64Decode(parts[1]);
		String signature = parts[2];

		return new DecodedJwtImpl(header, payload, signature);
	}

	private String base64Decode(String encoded) {
		byte[] decodedBytes = Base64.getDecoder().decode(encoded);
		return new String(decodedBytes, StandardCharsets.UTF_8);
	}

	static class DecodedJwtImpl implements DecodedJwt {

		private String header;
		private String payload;
		private String signature;

		DecodedJwtImpl(String header, String payload, String signature) {
			this.header = header;
			this.payload = payload;
			this.signature = signature;
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
	}
}
