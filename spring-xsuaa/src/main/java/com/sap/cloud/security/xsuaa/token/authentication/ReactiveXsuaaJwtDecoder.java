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
import java.util.Collection;
import java.util.concurrent.TimeUnit;

public class ReactiveXsuaaJwtDecoder implements ReactiveJwtDecoder {

	private final ReactiveJwtDecoderFactory jwtDecoderFactory;
	private final Cache<String, ReactiveJwtDecoder> cache;
	private final OAuth2TokenValidator<Jwt> tokenValidator;
	private Collection<PostValidationAction> postValidationActions;
	private TokenInfoExtractor tokenInfoExtractor;

	ReactiveXsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds,
			int cacheSize, ReactiveJwtDecoderFactory jwtDecoderFactory, OAuth2TokenValidator<Jwt> tokenValidator,
			Collection<PostValidationAction> postValidationActions) {
		cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS).maximumSize(cacheSize)
				.build();
		this.tokenInfoExtractor = new XsuaaTokenInfoExtractor(xsuaaServiceConfiguration.getUaaDomain());
		this.postValidationActions = postValidationActions != null ? postValidationActions : new ArrayList<>();
		this.tokenValidator = tokenValidator;
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
			String jku = tokenInfoExtractor.getJku(jwtToken);
			String cacheKey = jku + tokenInfoExtractor.getKid(jwtToken);
			return cache.get(cacheKey, k -> jwtDecoderFactory.create(jku, tokenValidator));
		}).flatMap(decoder -> decoder.decode(token))
				.doOnSuccess(jwt -> postValidationActions.forEach(act -> act.perform(jwt)));
	}

}
