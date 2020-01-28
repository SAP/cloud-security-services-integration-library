package com.sap.cloud.security.token;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.regex.Pattern;

import static com.sap.cloud.security.token.TokenClaims.EXPIRATION;
import static com.sap.cloud.security.token.TokenClaims.NOT_BEFORE;

/**
 * Decodes and parses encoded access token (JWT) Token and provides access to
 * token header parameters and claims.
 */
public abstract class AbstractToken implements Token {
	private final DefaultJsonObject tokenHeader;
	private final DefaultJsonObject tokenBody;
	private final String accessToken;

	public AbstractToken(@Nonnull DecodedJwt decodedJwt) {
		this(decodedJwt.getHeader(), decodedJwt.getPayload(), decodedJwt.getEncodedToken());
	}

	/**
	 * Creates a Token object for simple access to the header parameters and its
	 * claims.
	 * 
	 * @param accessToken
	 *            the encoded access token (Jwt or OIDC), e.g. from the
	 *            Authorization Header.
	 */
	public AbstractToken(@Nonnull String accessToken) {
		this(Base64JwtDecoder.getInstance().decode(removeBearer(accessToken)));
	}

	AbstractToken(String jsonHeader, String jsonPayload, String accessToken) {
		tokenHeader = new DefaultJsonObject(jsonHeader);
		tokenBody = new DefaultJsonObject(jsonPayload);
		this.accessToken = accessToken;
	}

	@Nullable
	@Override
	public String getHeaderParameterAsString(@Nonnull String headerName) {
		return tokenHeader.getAsString(headerName);
	}

	@Override
	public boolean hasClaim(@Nonnull String claimName) {
		return tokenBody.contains(claimName);
	}

	@Override
	public boolean hasHeaderParameter(@Nonnull String parameterName) {
		return tokenHeader.contains(parameterName);
	}

	@Nullable
	@Override
	public String getClaimAsString(@Nonnull String claimName) {
		return tokenBody.getAsString(claimName);
	}

	@Nullable
	@Override
	public List<String> getClaimAsStringList(@Nonnull String claimName) {
		return tokenBody.getAsList(claimName, String.class);
	}

	@Nullable
	@Override
	public JsonObject getClaimAsJsonObject(String claimName) {
		return tokenBody.getJsonObject(claimName);
	}

	@Nullable
	@Override
	public Instant getExpiration() {
		return tokenBody.getAsInstant(EXPIRATION);
	}

	@Override
	public boolean isExpired() {
		return getExpiration() == null ? false
				: getExpiration().isBefore(LocalDateTime.now().toInstant(ZoneOffset.UTC));
	}

	@Nullable
	@Override
	public Instant getNotBefore() {
		return tokenBody.getAsInstant(NOT_BEFORE);
	}

	@Override
	public String getAccessToken() {
		return accessToken;
	}

	@Override
	public String getBearerAccessToken() {
		return "Bearer " + accessToken;
	}

	@Override
	public List<String> getAudiences() {
		return getClaimAsStringList(TokenClaims.AUDIENCE);
	}

	private static String removeBearer(@Nonnull String accessToken) {
		Assertions.assertHasText(accessToken, "accessToken must not be null / empty");
		Pattern bearerPattern = Pattern.compile("[B|b]earer ");
		return bearerPattern.matcher(accessToken).replaceFirst("");
	}

}
