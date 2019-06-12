package com.sap.cloud.security.xsuaa.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class AuthenticationToken extends JwtAuthenticationToken {

	public AuthenticationToken(Jwt jwt, Collection<GrantedAuthority> authorities) {
		super(jwt, authorities);
	}

	@Override
	public Object getPrincipal() {
		TokenImpl token = new TokenImpl(getToken());
		token.setAuthorities(this.getAuthorities());
		return token;
	}

}
