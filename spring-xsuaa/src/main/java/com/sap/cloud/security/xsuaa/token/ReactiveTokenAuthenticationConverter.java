package com.sap.cloud.security.xsuaa.token;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

import reactor.core.publisher.Mono;

public class ReactiveTokenAuthenticationConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
	TokenAuthenticationConverter converter;

	public ReactiveTokenAuthenticationConverter(XsuaaServiceConfiguration xsuaaServiceConfiguration) {
		this.converter = new TokenAuthenticationConverter(xsuaaServiceConfiguration.getAppId());
		this.converter.setLocalScopeAsAuthorities(false);
	}

	@Override
	public Mono<AbstractAuthenticationToken> convert(Jwt jwt) {
		return Mono.just(converter.convert(jwt));
	}

}
