/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token;

import com.sap.cloud.security.json.DefaultJsonObject;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.xsuaa.Assertions;
import com.sap.cloud.security.xsuaa.jwt.Base64JwtDecoder;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import org.json.JSONObject;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Principal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;
import java.util.regex.Pattern;

import static com.sap.cloud.security.token.TokenClaims.*;
import static com.sap.cloud.security.token.TokenClaims.XSUAA.*;

/**
 * Decodes and parses encoded JSON Web Token (JWT) and provides access to token
 * header parameters and claims.
 */
public abstract class AbstractToken implements Token {
	private static final long serialVersionUID = 2204172041950251807L;

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

	@Nonnull
	@Override
	public List<String> getClaimAsStringList(@Nonnull String claimName) {
		return tokenBody.getAsStringList(claimName);
	}

	@Nullable
	@Override
	public JsonObject getClaimAsJsonObject(@Nonnull String claimName) {
		return tokenBody.getJsonObject(claimName);
	}

	@Nullable
	@Override
	public Instant getExpiration() {
		return tokenBody.getAsInstant(EXPIRATION);
	}

	@Override
	public boolean isExpired() {
		return getExpiration() == null || getExpiration().isBefore(LocalDateTime.now().toInstant(ZoneOffset.UTC));
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

	public boolean isXsuaaToken() {
		if (tokenBody.contains(EXTERNAL_ATTRIBUTE)) {
			JsonObject externalAttributes = tokenBody.getJsonObject(EXTERNAL_ATTRIBUTE);
			return "XSUAA".equalsIgnoreCase(externalAttributes.getAsString(EXTERNAL_ATTRIBUTE_ENHANCER));
		}
		return false;
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
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof Token))
			return false;
		Token that = (Token) obj;
		return getTokenValue().equals(that.getTokenValue());
	}

	@Override
	public int hashCode() {
		return Objects.hash(getTokenValue());
	}

	@Override
	public String getZoneId() {
		return getClaimAsString(SAP_GLOBAL_ZONE_ID);
	}

	@Override
	public String toString() {
		return decodedJwt.toString();
	}

	@Override
	public Map<String, Object> getHeaders() {
		return new JSONObject(decodedJwt.getHeader()).toMap();
	}

	@Override
	public Map<String, Object> getClaims() {
		return new JSONObject(decodedJwt.getPayload()).toMap();
	}
}
