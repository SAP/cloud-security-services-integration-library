package com.sap.cloud.security.xsuaa.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Internal class used to expose the {@link Token} implementation as the
 * standard Principal for Spring Security Jwt handling.
 *
 * @see TokenAuthenticationConverter
 * @see XsuaaToken
 */
public class AuthenticationToken extends JwtAuthenticationToken {
	private static final long serialVersionUID = -3779129534612771294L;

	private Token token;

	public AuthenticationToken(Jwt jwt, Collection<GrantedAuthority> authorities) {
		super(jwt, authorities);

		// Here is where the actual magic happens.
		// The Jwt is exchanged for another implementation.
		XsuaaToken token = new XsuaaToken(getToken());
		token.setAuthorities(this.getAuthorities());
		this.token = token;
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
