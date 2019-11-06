package com.sap.cloud.security.token;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Instant;
import java.util.List;

import static com.sap.cloud.security.token.TokenClaims.*;

public class TokenImpl implements Token {

	private final DefaultJsonObject headerJsonObject;
	private final DefaultJsonObject payloadJsonObject;
	private final String appToken;

	public TokenImpl(DecodedJwt decodedJwt) {
		this(decodedJwt.getHeader(), decodedJwt.getPayload(), decodedJwt.getEncodedToken());
	}

	public TokenImpl(String appToken) {
		this(Base64JwtDecoder.getInstance().decode(appToken));
	}

	TokenImpl(String jsonHeader, String jsonPayload, String appToken) {
		headerJsonObject = new DefaultJsonObject(jsonHeader);
		payloadJsonObject = new DefaultJsonObject(jsonPayload);
		this.appToken = appToken;
	}

	@Nullable
	@Override
	public String getHeaderParameterAsString(@Nonnull String headerName) {
		return headerJsonObject.getAsString(headerName);
	}

	@Override
	public boolean containsClaim(@Nonnull String claimName) {
		return payloadJsonObject.contains(claimName);
	}

	@Nullable
	@Override
	public String getClaimAsString(@Nonnull String claimName) {
		return payloadJsonObject.getAsString(claimName);
	}

	@Nullable
	@Override
	public List<String> getClaimAsStringList(@Nonnull String claimName) {
		return payloadJsonObject.getAsList(claimName, String.class);
	}

	@Nullable
	@Override
	public Instant getExpiration() {
		return payloadJsonObject.getAsInstant(EXPIRATION);
	}

	@Nullable
	@Override
	public Instant getNotBefore() {
		return payloadJsonObject.getAsInstant(NOT_BEFORE);
	}

	@Override
	public String getAppToken() {
		return appToken;
	}
}
