package com.sap.cloud.security.token;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Principal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import static com.sap.cloud.security.token.TokenClaims.EXPIRATION;
import static com.sap.cloud.security.token.TokenClaims.NOT_BEFORE;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.ISSUED_AT;

/**
 * Decodes and parses encoded JSON Web Token (JWT) and provides access to token
 * header parameters and claims.
 */
public abstract class AbstractToken implements Token {
	private final DecodedJwt decodedJwt;
	protected final DefaultJsonObject tokenHeader;
	protected final DefaultJsonObject tokenBody;

	public AbstractToken(@Nonnull DecodedJwt decodedJwt) {
		this.tokenHeader = new DefaultJsonObject(decodedJwt.getHeader());
		this.tokenBody = new DefaultJsonObject(decodedJwt.getPayload());
		this.decodedJwt = decodedJwt;
	}

	/**
	 * Creates a Token object for simple access to the header parameters and its
	 * claims.
	 * 
	 * @param jwtToken
	 *            the encoded JWT token (access_token or id_token), e.g. from the
	 *            Authorization Header.
	 */
	public AbstractToken(@Nonnull String jwtToken) {
		this(Base64JwtDecoder.getInstance().decode(removeBearer(jwtToken)));
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
		return getExpiration() == null ? true
				: getExpiration().isBefore(LocalDateTime.now().toInstant(ZoneOffset.UTC));
	}

	@Nullable
	@Override
	public Instant getNotBefore() {
		return tokenBody.contains(NOT_BEFORE)
				? tokenBody.getAsInstant(NOT_BEFORE)
				: tokenBody.getAsInstant(ISSUED_AT);
	}

	@Override
	public String getTokenValue() {
		return decodedJwt.getEncodedToken();
	}

	@Override
	public Set<String> getAudiences() {
		Set<String> audiences = new LinkedHashSet<>();
		audiences.addAll(getClaimAsStringList(TokenClaims.AUDIENCE));
		return audiences;
	}

	protected Principal createPrincipalByName(String name) {
		return new Principal() {
			@Override
			public boolean equals(Object o) {
				if (this == o)
					return true;
				if (!(o instanceof Principal))
					return false;
				Principal that = (Principal) o;
				return getName().equals(that.getName());
			}

			@Override
			public int hashCode() {
				return Objects.hash(getName());
			}

			@Override
			public String getName() {
				return name;
			}
		};
	}

	private static String removeBearer(@Nonnull String jwtToken) {
		Assertions.assertHasText(jwtToken, "jwtToken must not be null / empty");
		Pattern bearerPattern = Pattern.compile("[B|b]earer ");
		return bearerPattern.matcher(jwtToken).replaceFirst("");
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (!(o instanceof AbstractToken))
			return false;
		AbstractToken that = (AbstractToken) o;
		return getTokenValue().equals(that.getTokenValue());
	}

	@Override
	public int hashCode() {
		return Objects.hash(getTokenValue());
	}

	@Override
	public String getZoneId() {
		return getClaimAsString(TokenClaims.SAP_GLOBAL_ZONE_ID);
	}

	@Override
	public String toString() {
		return decodedJwt.toString();
	}
}
