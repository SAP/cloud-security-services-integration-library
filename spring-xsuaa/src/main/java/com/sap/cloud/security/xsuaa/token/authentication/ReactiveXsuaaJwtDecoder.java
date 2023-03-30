/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.json.JSONObject;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_JKU;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_KID;

public class ReactiveXsuaaJwtDecoder implements ReactiveJwtDecoder {

	Cache<String, ReactiveJwtDecoder> cache;
	private List<OAuth2TokenValidator<Jwt>> tokenValidators = new ArrayList<>();
	private Collection<PostValidationAction> postValidationActions;
	private TokenInfoExtractor tokenInfoExtractor;

	// var arg it is only being converted to a List<OAuth2TokenValidator<Jwt>>,
	// therefore its type safe.
	ReactiveXsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds,
			int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators, Collection<PostValidationAction> postValidationActions) {
		cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS).maximumSize(cacheSize)
				.build();

		this.tokenInfoExtractor = new TokenInfoExtractor() {
			@Override
			public String getJku(JWT jwt) {
				return new JSONObject(jwt.getHeader().toString()).optString(CLAIM_JKU, null);
			}

			@Override
			public String getKid(JWT jwt) {
				return new JSONObject(jwt.getHeader().toString()).optString(CLAIM_KID, null);
			}

			@Override
			public String getUaaDomain(JWT jwt) {
				return xsuaaServiceConfiguration.getUaaDomain();
			}
		};

		this.tokenValidators.addAll(Arrays.asList(tokenValidators));
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
			String cacheKey = tokenInfoExtractor.getJku(jwtToken) + tokenInfoExtractor.getKid(jwtToken);
			return cache.get(cacheKey, k -> this.getDecoder(tokenInfoExtractor.getJku(jwtToken)));
		}).flatMap(decoder -> decoder.decode(token))
				.doOnSuccess(jwt -> postValidationActions.forEach(act -> act.perform(jwt)));
	}

	private ReactiveJwtDecoder getDecoder(String jku) {
		NimbusReactiveJwtDecoder decoder = new NimbusReactiveJwtDecoder(jku);
		decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(tokenValidators));
		return decoder;
	}

}
