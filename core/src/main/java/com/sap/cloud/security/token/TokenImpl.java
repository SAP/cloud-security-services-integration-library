package com.sap.cloud.security.token;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Instant;
import java.util.List;

public class TokenImpl implements Token {

	private final DefaultJsonObject jsonHeaderParser;
	private final DefaultJsonObject jsonPayloadParser;
	private final String appToken;

	public TokenImpl(String headerAsJsonString, String payloadAsJsonString, String appToken) {
		jsonHeaderParser = new DefaultJsonObject(headerAsJsonString);
		jsonPayloadParser = new DefaultJsonObject(payloadAsJsonString);
		this.appToken = appToken;
	}

	public TokenImpl(DecodedJwt decodedJwt) {
		jsonHeaderParser = new DefaultJsonObject(decodedJwt.getHeader());
		jsonPayloadParser = new DefaultJsonObject(decodedJwt.getPayload());
		this.appToken = decodedJwt.getEncodedToken();
	}


	@Nullable
	@Override
	public String getHeaderValueAsString(@Nonnull String headerName) {
		return jsonHeaderParser.getAsString(headerName);
	}

	@Override
	public boolean containsClaim(@Nonnull String claimName) {
		return jsonPayloadParser.contains(claimName);
	}

	@Nullable
	@Override
	public String getClaimAsString(@Nonnull String claimName) {
		return jsonPayloadParser.getAsString(claimName);
	}

	@Nullable
	@Override
	public List<String> getClaimAsStringList(@Nonnull String claimName) {
		return jsonPayloadParser.getAsList(claimName, String.class);
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
