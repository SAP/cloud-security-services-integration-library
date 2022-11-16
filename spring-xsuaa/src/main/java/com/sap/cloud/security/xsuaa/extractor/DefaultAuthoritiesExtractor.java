/**
 * SPDX-FileCopyrightText: 2018-2022 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.extractor;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import com.sap.cloud.security.xsuaa.token.TokenClaims;
import com.sap.cloud.security.xsuaa.token.XsuaaToken;

public class DefaultAuthoritiesExtractor extends JwtAuthenticationConverter implements AuthoritiesExtractor {

	public Collection<GrantedAuthority> getAuthorities(XsuaaToken jwt) {
		return extractAuthorities(jwt);
	}

	@Override
	@Deprecated
	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		List<String> scopes = jwt.getClaimAsStringList(TokenClaims.CLAIM_SCOPES);

		if (scopes == null) {
			return Collections.emptyList();
		}

		return scopes.stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
	}

}
