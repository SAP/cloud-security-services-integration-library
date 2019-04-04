package com.sap.cloud.security.xsuaa.token;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public class AuthenticationToken extends JwtAuthenticationToken {

	String appId;

	public AuthenticationToken(String appId, Jwt jwt, Collection<GrantedAuthority> authorities) {
		super(jwt, authorities);
		this.appId = appId;
	}

	@Override
	public Object getPrincipal() {
		TokenImpl token = new TokenImpl(getToken(), appId);
		token.setAuthorities(this.getAuthorities());
		return token;
	}

}
