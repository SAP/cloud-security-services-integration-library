package com.sap.cloud.security.xsuaa.token.authentication;

import java.text.ParseException;
import java.util.*;
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
	private final XsuaaServiceConfiguration xsuaaServiceConfiguration;
	private List<OAuth2TokenValidator<Jwt>> tokenValidators = new ArrayList<>();
	private Collection<PostValidationAction> postValidationActions;

	private static final String EXT_ATTR = "ext_attr";
	private static final String ZDN = "zdn";
	private static final String ZID = "zid";

	// var arg it is only being converted to a List<OAuth2TokenValidator<Jwt>>,
	// therefore its type safe.
	ReactiveXsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidity, int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators, Collection<PostValidationAction> postValidationActions) {
		cache = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.SECONDS).maximumSize(cacheSize).build();
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;

		this.tokenValidators.add(new JwtTimestampValidator());
		if (tokenValidators == null) {
			this.tokenValidators.add(new XsuaaAudienceValidator(xsuaaServiceConfiguration));
		} else {
			this.tokenValidators.addAll(Arrays.asList(tokenValidators));
		}
		this.postValidationActions = postValidationActions != null ? postValidationActions : Collections.EMPTY_LIST;
	}

	@Override
	public Mono<Jwt> decode(String token) throws JwtException {
		return Mono.just(token).map(jwtToken -> {
			try {
				return JWTParser.parse(jwtToken);
			} catch (ParseException e) {
				throw new JwtException("Error initializing JWT decoder:" + e.getMessage());
			}
		}).map(jwtToken -> {
			try {
				String subdomain = this.getSubdomain(jwtToken);
				String zoneId = jwtToken.getJWTClaimsSet().getStringClaim(ZID);
				return cache.get(subdomain, k -> this.getDecoder(zoneId, subdomain));
			} catch (ParseException e) {
				throw new JwtException("Error initializing JWT decoder:" + e.getMessage());
			}
		}).flatMap(decoder -> decoder.decode(token))
				.doOnSuccess(jwt -> postValidationActions.forEach(act -> act.perform(jwt)));
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
		decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(tokenValidators));
		return decoder;
	}

}
