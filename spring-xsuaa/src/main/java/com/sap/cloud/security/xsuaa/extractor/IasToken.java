/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.Token;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.Principal;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

import static com.sap.cloud.security.token.TokenClaims.SAP_GLOBAL_ZONE_ID;

class IasToken implements Token {

	private Jwt decodedToken;

	public IasToken(Jwt jwt) {
		this.decodedToken = jwt;
	}

	@Nullable
	@Override
	public String getHeaderParameterAsString(@Nonnull String headerName) {
		return decodedToken.getHeaders().get(headerName).toString();
	}

	@Override
	public boolean hasHeaderParameter(@Nonnull String headerName) {
		return decodedToken.getHeaders().containsValue(headerName);
	}

	@Override
	public boolean hasClaim(@Nonnull String claimName) {
		return decodedToken.hasClaim(claimName);
	}

	@Nullable
	@Override
	public String getClaimAsString(@Nonnull String claimName) {
		return decodedToken.getClaimAsString(claimName);
	}

	@Override
	public List<String> getClaimAsStringList(@Nonnull String claimName) {
		return decodedToken.getClaimAsStringList(claimName);
	}

	@Nullable
	@Override
	public JsonObject getClaimAsJsonObject(@Nonnull String claimName) {
		return decodedToken.getClaim(claimName);
	}

	@Nullable
	@Override
	public Instant getExpiration() {
		return decodedToken.getExpiresAt();
	}

	@Override
	public boolean isExpired() {
		return Objects.requireNonNull(decodedToken.getExpiresAt(), "Token expiration time is missing")
				.isBefore(Instant.now());
	}

	@Nullable
	@Override
	public Instant getNotBefore() {
		return decodedToken.getNotBefore();
	}

	@Override
	public String getTokenValue() {
		return decodedToken.getTokenValue();
	}

	@Override
	public Principal getPrincipal() {
		return null;
	}

	@Override
	public Service getService() {
		return Service.IAS;
	}

	@Override
	public String getZoneId() {
		return decodedToken.getClaimAsString(SAP_GLOBAL_ZONE_ID);
	}
}
