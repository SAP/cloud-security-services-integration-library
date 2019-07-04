package com.sap.cloud.security.xsuaa.token.authentication;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.util.Assert;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;

public class XsuaaJwtDecoder implements JwtDecoder {
	private final Logger logger = LoggerFactory.getLogger(getClass());

	Cache<String, JwtDecoder> cache;
	private String uaaDomain;
	private OAuth2TokenValidator<Jwt> tokenValidators;

	XsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds, int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators) {
		cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS).maximumSize(cacheSize)
				.build();
		this.uaaDomain = xsuaaServiceConfiguration.getUaaDomain();
		this.tokenValidators = tokenValidators;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		Assert.notNull(token, "token is required");
		JWT jwt;

		try {
			jwt = JWTParser.parse(token);
		} catch (ParseException ex) {
			throw new JwtException("Error initializing JWT decoder: " + ex.getMessage());
		}

		String jku = (String) jwt.getHeader().toJSONObject().getOrDefault("jku", null);
		String kid = (String) jwt.getHeader().toJSONObject().getOrDefault("kid", null);

		try {
			canVerifyWithOnlineKey(jku, kid, uaaDomain);
			validateJKU(jku, uaaDomain);
			return verifyWithOnlineKey(token, jku, kid);
		} catch (JwtValidationException ex) {
			throw ex;
		} catch (JwtException ex) {
			throw new JwtException("JWT verification failed: " + ex.getMessage());
		}
	}

	private void canVerifyWithOnlineKey(String jku, String kid, String uaadomain) {
		if (jku != null && kid != null && uaadomain != null) {
			return;
		}

		List<String> nullParams = new ArrayList<>();
		if (jku == null)
			nullParams.add("jku");
		if (kid == null)
			nullParams.add("kid");
		if (uaadomain == null)
			nullParams.add("uaadomain");

		throw new JwtException(String.format("Cannot verify with online token key, %s is null",
				String.join(", ", nullParams)));
	}

	private void validateJKU(String jku, String uaadomain) {
		try {
			URI jkuUri = new URI(jku);
			if (jkuUri.getHost() == null) {
				throw new JwtException("JKU of token is not valid");
			} else if (!jkuUri.getHost().endsWith(uaadomain)) {
				logger.warn(String.format("Error: Do not trust jku '%s' because it does not match uaa domain '%s'",
						jku, uaadomain));
				throw new JwtException("JKU of token header is not trusted");
			}
		} catch (URISyntaxException e) {
			throw new JwtException("JKU of token header is not valid");
		}
	}

	private Jwt verifyWithOnlineKey(String token, String jku, String kid) {
		String cacheKey = jku + kid;
		JwtDecoder decoder = cache.get(cacheKey, k -> this.getDecoder(jku));
		return decoder.decode(token);
	}

	private JwtDecoder getDecoder(String jku) {
		NimbusJwtDecoderJwkSupport decoder = new NimbusJwtDecoderJwkSupport(jku);
		decoder.setJwtValidator(tokenValidators);
		return decoder;
	}
}
