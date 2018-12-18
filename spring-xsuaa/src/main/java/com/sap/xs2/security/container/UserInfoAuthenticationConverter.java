package com.sap.xs2.security.container;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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
		Collection<String> scopes = this.getScopes(jwt);
		return scopes.stream().map(authority -> authority).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	private Collection<String> getScopes(Jwt jwt) {
		List<String> scopesList = jwt.getClaimAsStringList(UserInfo.SCOPE);
		return scopesList != null ? scopesList : Collections.emptyList();
	}
}