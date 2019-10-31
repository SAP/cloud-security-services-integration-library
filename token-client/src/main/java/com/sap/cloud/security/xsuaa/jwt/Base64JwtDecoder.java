package com.sap.cloud.security.xsuaa.jwt;

import com.sap.cloud.security.xsuaa.Assertions;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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
		private final Map<String, Object> payloadMap;
		private final Map<String, Object> headerMap;

		DecodedJwtImpl(String encodedJwt, String header, String payload, String signature) {
			this.header = header;
			this.payload = payload;
			this.signature = signature;
			this.encodedJwt = encodedJwt;
			this.headerMap = createMapFromJsonString(header);
			this.payloadMap = createMapFromJsonString(payload);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public String getHeaderValue(String name) {
			Object value = headerMap.get(name);
			return extractStringOrNull(value);
		}

		@Override
		public String getPayload() {
			return payload;
		}

		@Override public String getPayloadValue(String name) {
			Object value = payloadMap.get(name);
			return extractStringOrNull(value);
		}

		@Override
		public String getSignature() {
			return signature;
		}

		@Override public String getEncodedToken() {
			return encodedJwt;
		}

		private Map<String, Object> createMapFromJsonString(String header) {
			try {
				JSONObject jsonObject = new JSONObject(header);
				return jsonObject.toMap();
			} catch (JSONException e) {
				return new HashMap<>();
			}
		}

		private String extractStringOrNull(Object value) {
			return Optional.ofNullable(value).map(Object::toString).orElse(null);
		}

	}
}
