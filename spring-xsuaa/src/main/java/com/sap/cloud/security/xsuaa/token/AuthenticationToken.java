/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.Serial;
import java.util.Collection;

/**
 * Internal class used to expose the {@link Token} implementation as the standard Principal for Spring Security Jwt
 * handling.
 *
 * @see TokenAuthenticationConverter
 * @see XsuaaToken
 */
public class AuthenticationToken extends JwtAuthenticationToken {

	@Serial
	private static final long serialVersionUID = -3779129534612771294L;

	private final Token token;

	public AuthenticationToken(Jwt jwt, Collection<GrantedAuthority> authorities) {
		super(jwt, authorities);

		// Here is where the actual magic happens.
		// The Jwt is exchanged for another implementation.
		XsuaaToken xsuaaToken = new XsuaaToken(getToken());
		xsuaaToken.setAuthorities(this.getAuthorities());
		this.token = xsuaaToken;
	}

	@Override
	public Object getPrincipal() {
		return token;
	}

	@Override
	public String getName() {
		return token.getUsername();
	}
}
