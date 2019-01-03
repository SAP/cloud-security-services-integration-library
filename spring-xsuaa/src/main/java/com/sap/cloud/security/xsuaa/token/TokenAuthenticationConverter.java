/**
 * Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved.
 * This file is licensed under the Apache Software License,
 * v. 2 except as noted otherwise in the LICENSE file
 * https://github.com/SAP/cloud-security-xsuaa-integration/blob/master/LICENSE
 */
package com.sap.cloud.security.xsuaa.token;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

/**
 * Converter for xsuaa jwt token that stores authorization data like scopes inside the token.
 */
public class TokenAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

	protected String appId;

	public TokenAuthenticationConverter(String appId) {
		this.appId = appId;
	}

	public TokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.appId = xsuaaServiceConfiguration.getAppId();
	}

	public final AbstractAuthenticationToken convert(Jwt jwt) {
		return new AuthenticationToken(appId, jwt, extractAuthorities(jwt));
	}

	protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		Collection<String> scopeAuthorities = getScopes(jwt);
		Collection<String> customAuthorities = getCustomAuthorities(new TokenImpl(jwt, appId));

		Stream<String> authorities = Stream.of(scopeAuthorities, customAuthorities).flatMap(Collection::stream);
		return authorities.map(authority -> authority).map(SimpleGrantedAuthority::new).collect(Collectors.toList());
	}

	protected Collection<String> getCustomAuthorities(Token token) {
		return Collections.emptyList();
	}

	protected Collection<String> getScopes(Jwt jwt) {
		List<String> scopesList = jwt.getClaimAsStringList(Token.CLAIM_SCOPES);
		return scopesList != null ? scopesList : Collections.emptyList();
	}
}