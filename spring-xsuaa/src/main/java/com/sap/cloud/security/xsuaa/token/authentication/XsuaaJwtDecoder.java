package com.sap.cloud.security.xsuaa.token.authentication;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_JKU;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_KID;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
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
	private OAuth2TokenValidator<Jwt> tokenValidators;
	private Collection<PostValidationAction> postValidationActions;
	private TokenInfoExtractor tokenInfoExtractor;

	XsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds, int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators) {
		cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS).maximumSize(cacheSize)
				.build();
		this.tokenValidators = tokenValidators;

		this.tokenInfoExtractor = new TokenInfoExtractor() {
			@Override
			public String getJku(JWT jwt) {
				return (String) jwt.getHeader().toJSONObject().getOrDefault(CLAIM_JKU, null);
			}

			@Override
			public String getKid(JWT jwt) {
				return (String) jwt.getHeader().toJSONObject().getOrDefault(CLAIM_KID, null);
			}

			@Override
			public String getUaaDomain(JWT jwt) {
				return xsuaaServiceConfiguration.getUaaDomain();
			}
		};
	}

	XsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds, int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators, Collection<PostValidationAction> postValidationActions) {
		this(xsuaaServiceConfiguration, cacheValidityInSeconds, cacheSize, tokenValidators);
		this.postValidationActions = postValidationActions;
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

		String jku = tokenInfoExtractor.getJku(jwt);
		String kid = tokenInfoExtractor.getKid(jwt);
		String uaaDomain = tokenInfoExtractor.getUaaDomain(jwt);

		try {
			canVerifyWithOnlineKey(jku, kid, uaaDomain);
			validateJKU(jku, uaaDomain);
			Jwt verifiedToken = verifyWithOnlineKey(token, jku, kid);

			if (postValidationActions != null) {
				postValidationActions.forEach(act -> act.perform(verifiedToken));
			}
			return verifiedToken;
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

	public void setTokenInfoExtractor(TokenInfoExtractor tokenInfoExtractor) {
		this.tokenInfoExtractor = tokenInfoExtractor;
	}
}
