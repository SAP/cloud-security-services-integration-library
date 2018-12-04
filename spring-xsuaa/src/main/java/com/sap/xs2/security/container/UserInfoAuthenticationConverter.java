package com.sap.xs2.security.container;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class UserInfoAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	private String appId;

	public UserInfoAuthenticationConverter(String appId) {
		this.appId = appId;
	}

	public UserInfoAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.appId = xsuaaServiceConfiguration.getAppId();
	}


	public final AbstractAuthenticationToken convert(Jwt jwt) {
		try {
			Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
			return new UserInfoAuthenticationToken(appId, jwt, authorities);
		} catch (BadJOSEException | JOSEException | ParseException e) {
			return null;
		}
	}

	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		return this.getScopes(jwt).stream().map(authority -> authority).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	private Collection<String> getScopes(Jwt jwt) {

		Object scopes = jwt.getClaims().get("scope");
		if (scopes instanceof String) {
			if (StringUtils.hasText((String) scopes)) {
				return Arrays.asList(((String) scopes).split(" "));
			} else {
				return Collections.emptyList();
			}
		} else if (scopes instanceof Collection) {
			return (Collection<String>) scopes;
		}
		return Collections.emptyList();
	}
}