package com.sap.cloud.security.xsuaa.token;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;

public class AuthenticationToken extends JwtAuthenticationToken {

	String appId;

	public AuthenticationToken(String appId, Jwt jwt, Collection<GrantedAuthority> authorities) {
		super(jwt, authorities);
		this.appId = appId;
	}

	@Override
	public Object getPrincipal() {
		return new TokenImpl(getToken(), appId);
	}

}
