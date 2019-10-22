package com.sap.cloud.security.xsuaa.token.authentication;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class ReactiveXsuaaJwtDecoder implements ReactiveJwtDecoder {

	private final ReactiveJwtDecoderFactory jwtDecoderFactory;
	Cache<String, ReactiveJwtDecoder> cache;
	private final OAuth2TokenValidator<Jwt> tokenValidator;
	private Collection<PostValidationAction> postValidationActions;
	private TokenInfoExtractor tokenInfoExtractor;

	private static final String EXT_ATTR = "ext_attr";
	private static final String ZDN = "zdn";
	private static final String ZID = "zid";

	// var arg it is only being converted to a List<OAuth2TokenValidator<Jwt>>,
	// therefore its type safe.
	ReactiveXsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds,
			int cacheSize, ReactiveJwtDecoderFactory jwtDecoderFactory, OAuth2TokenValidator<Jwt> tokenValidator,
			Collection<PostValidationAction> postValidationActions) {
		cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS).maximumSize(cacheSize)
				.build();
		this.tokenInfoExtractor = new XsuaaTokenInfoExtractor(xsuaaServiceConfiguration.getUaaDomain());
		this.tokenValidator = tokenValidator;
		this.postValidationActions = postValidationActions != null ? postValidationActions : new ArrayList<>();
		this.jwtDecoderFactory = jwtDecoderFactory;
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
			String cacheKey = tokenInfoExtractor.getJku(jwtToken) + tokenInfoExtractor.getKid(jwtToken);
			return cache.get(cacheKey, k -> this.getDecoder(tokenInfoExtractor.getJku(jwtToken)));
		}).flatMap(decoder -> decoder.decode(token))
				.doOnSuccess(jwt -> postValidationActions.forEach(act -> act.perform(jwt)));
	}

	private ReactiveJwtDecoder getDecoder(String jku) {
		return jwtDecoderFactory.create(jku, tokenValidator);
	}

}
