package com.sap.cloud.security.xsuaa.token.authentication;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

import reactor.core.publisher.Mono;

public class ReactiveXsuaaJwtDecoder implements ReactiveJwtDecoder {

	private XsuaaJwtDecoder xsuaaJwtDecoder;

	ReactiveXsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidity, int cacheSize) {
		xsuaaJwtDecoder = new XsuaaJwtDecoder(xsuaaServiceConfiguration, cacheValidity, cacheSize);
	}

	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		return Mono.just(xsuaaJwtDecoder.decode(token));
	}

}
