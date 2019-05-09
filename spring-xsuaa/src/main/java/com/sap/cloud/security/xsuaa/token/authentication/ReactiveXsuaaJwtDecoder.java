package com.sap.cloud.security.xsuaa.token.authentication;

import java.text.ParseException;
import java.util.concurrent.TimeUnit;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

import net.minidev.json.JSONObject;
import reactor.core.publisher.Mono;

public class ReactiveXsuaaJwtDecoder implements ReactiveJwtDecoder {

	Cache<String, ReactiveJwtDecoder> cache;
	private XsuaaServiceConfiguration xsuaaServiceConfiguration;

	private static final String EXT_ATTR = "ext_attr";
	private static final String ZDN = "zdn";
	private static final String ZID = "zid";

	ReactiveXsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidity, int cacheSize) {
		cache = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.SECONDS).maximumSize(cacheSize).build();
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;
	}

	@Override
	public Mono<Jwt> decode(String token) throws JwtException {

		return Mono.just(token).flatMap(RENAME_LATER -> {
			try {
				return Mono.just(JWTParser.parse(RENAME_LATER));
			} catch (ParseException e) {
				throw new JwtException("Error initializing JWT  decoder:" + e.getMessage());
			}
		}).zipWhen(jwt -> Mono.just(jwt).map(jwt2 -> {
			try {
				return this.getSubdomain(jwt2);
			} catch (ParseException e) {
				throw new JwtException("Error initializing JWT  decoder:" + e.getMessage());
			}
		}), (jwt, subdomain) -> {

			try {
				String zoneId = jwt.getJWTClaimsSet().getStringClaim(ZID);
				return cache.get(subdomain, k -> this.getDecoder(zoneId, subdomain));
			} catch (ParseException e) {
				throw new JwtException("Error initializing JWT  decoder:" + e.getMessage());
			}
		}).flatMap(decoder -> decoder.decode(token));
	}

	protected String getSubdomain(JWT jwt) throws ParseException {
		String subdomain = "";
		JSONObject extAttr = jwt.getJWTClaimsSet().getJSONObjectClaim(EXT_ATTR);
		if (extAttr != null && extAttr.getAsString(ZDN) != null) {
			subdomain = extAttr.getAsString(ZDN);
		}
		return subdomain;
	}

	private ReactiveJwtDecoder getDecoder(String zid, String subdomain) {
		String url = xsuaaServiceConfiguration.getTokenKeyUrl(zid, subdomain);
		NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(url);

		OAuth2TokenValidator<Jwt> validators = new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(),
				new XsuaaAudienceValidator(xsuaaServiceConfiguration));
		decoder.setJwtValidator(validators);
		return decoder;
	}

}
