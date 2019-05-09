package com.sap.cloud.security.xsuaa.token.authentication;

import java.text.ParseException;
import java.util.concurrent.TimeUnit;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

import net.minidev.json.JSONObject;
import reactor.core.Exceptions;
import reactor.core.publisher.Mono;

public class ReactiveXsuaaJwtDecoder implements ReactiveJwtDecoder {

	Cache<String, JwtDecoder> cache;
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	ReactiveXsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidity, int cacheSize) {
		cache = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.SECONDS).maximumSize(cacheSize).build();
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;
	}

	private static final String EXT_ATTR = "ext_attr";
	private static final String ZDN = "zdn";

	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		Mono<JWT> jwt = Mono.just(token).map(RENAME_LATER -> {
			try {
				return JWTParser.parse(RENAME_LATER);
			} catch (ParseException e) {
				Exceptions.propagate(e);
			}
			return null;
		});

		return Mono.zip(jwt.map(jwt2 -> {
			try {
				return this.getSubdomain(jwt2);
			} catch (ParseException e) {
				return null;
			}
		}), jwt.map(jwt2 -> {
			try {
				return jwt2.getJWTClaimsSet().getStringClaim("zid");
			} catch (ParseException e) {
				return null;
			}
		})).map(tuple -> {
			return cache.get(tuple.getT1(), k -> this.getDecoder(tuple.getT2(), tuple.getT1()));
		}).map(decoder -> decoder.decode(token));
	}

	protected String getSubdomain(JWT jwt) throws ParseException {
		String subdomain = "";
		JSONObject extAttr = jwt.getJWTClaimsSet().getJSONObjectClaim(EXT_ATTR);
		if (extAttr != null && extAttr.getAsString(ZDN) != null) {
			subdomain = extAttr.getAsString(ZDN);
		}
		return subdomain;
	}

	private JwtDecoder getDecoder(String zid, String subdomain) {
		String url = xsuaaServiceConfiguration.getTokenKeyUrl(zid, subdomain);
		NimbusJwtDecoderJwkSupport decoder = new NimbusJwtDecoderJwkSupport(url);
		OAuth2TokenValidator<Jwt> validators = new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(),
				new XsuaaAudienceValidator(xsuaaServiceConfiguration));
		decoder.setJwtValidator(validators);
		return decoder;
	}

}
