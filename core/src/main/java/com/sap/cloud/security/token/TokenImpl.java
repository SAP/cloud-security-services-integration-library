package com.sap.cloud.security.token;

import com.sap.cloud.security.json.JSONParser;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Instant;
import java.util.List;

public class TokenImpl implements Token {

	private final JSONParser jsonHeaderParser;
	private final JSONParser jsonPayloadParser;
	private final String appToken;

	public TokenImpl(String headerAsJsonString, String payloadAsJsonString, String appToken) {
		jsonHeaderParser = new JSONParser(headerAsJsonString);
		jsonPayloadParser = new JSONParser(payloadAsJsonString);
		this.appToken = appToken;
	}

	@Nullable
	@Override
	public String getHeaderValueAsString(@Nonnull String headerName) {
		return jsonHeaderParser.getValueAsString(headerName);
	}

	@Override
	public boolean containsClaim(@Nonnull String claimName) {
		return jsonPayloadParser.contains(claimName);
	}

	@Nullable
	@Override
	public String getClaimAsString(@Nonnull String claimName) {
		return jsonPayloadParser.getValueAsString(claimName);
	}

	@Nullable
	@Override
	public List<String> getClaimAsStringList(@Nonnull String claimName) {
		return jsonPayloadParser.getValueAsList(claimName, String.class);
	}

	@Nullable
	@Override
	public List<String> getScopes() {
		return getClaimAsStringList("scopes");
	}

	@Nullable
	@Override
	public Instant getExpiration() {
		// TODO 04.11.19 c5295400: TODO
		return null;
	}

	@Override
	public String getAppToken() {
		return appToken;
	}
}
