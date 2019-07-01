package com.sap.cloud.security.xsuaa.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Internal class used to expose the {@link Token} implementation as the standard Principal for Spring
 * Security Jwt handling.
 *
 * @see TokenAuthenticationConverter
 * @see TokenImpl
 */
public class AuthenticationToken extends JwtAuthenticationToken {

	public AuthenticationToken(Jwt jwt, Collection<GrantedAuthority> authorities) {
		super(jwt, authorities);
	}

	@Override
	public Object getPrincipal() {
		// Here is where the actual magic happens.
		// The Jwt is exchanged for another implementation.
		TokenImpl token = new TokenImpl(getToken());
		token.setAuthorities(this.getAuthorities());
		return token;
	}

}
