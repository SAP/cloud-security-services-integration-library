package com.sap.xs2.security.container;

import java.text.ParseException;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;

public class UserInfoAuthenticationToken extends JwtAuthenticationToken {

	String appId;

	public UserInfoAuthenticationToken(String appId, Jwt jwt, Collection<GrantedAuthority> authorities) throws BadJOSEException, JOSEException, ParseException {
		super(jwt, authorities);
		this.appId = appId;
	}

	@Override
	public Object getPrincipal() {
		return new UserInfo(getToken(), appId);
	}

}
