/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 *<p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.xsuaa.token.authentication;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_JKU;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_KID;
import static org.springframework.util.StringUtils.hasText;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Duration;
import java.util.*;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

public class XsuaaJwtDecoder implements JwtDecoder {
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final XsuaaServiceConfiguration xsuaaServiceConfiguration;
	private final Duration cacheValidityInSeconds;
	private final int cacheSize;

	com.github.benmanes.caffeine.cache.Cache<String, JwtDecoder> cache;
	private final OAuth2TokenValidator<Jwt> tokenValidators;
	private final Collection<PostValidationAction> postValidationActions;
	private TokenInfoExtractor tokenInfoExtractor;
	private RestOperations restOperations;

	XsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds, int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators, Collection<PostValidationAction> postValidationActions) {

		this.cacheValidityInSeconds = Duration.ofSeconds(cacheValidityInSeconds);
		this.cacheSize = cacheSize;
		this.cache = Caffeine.newBuilder().expireAfterWrite(this.cacheValidityInSeconds)
				.maximumSize(this.cacheSize)
				.build();
		this.tokenValidators = tokenValidators;
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;

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
		this.postValidationActions = postValidationActions != null ? postValidationActions : Collections.emptyList();
	}

	@Override
	/**
	 * @throws BadJwtException
	 *             as of version 2.10.0 (instead of JwtException)
	 * @see https://github.com/spring-projects/spring-security/issues/9395
	 * @see https://github.com/spring-projects/spring-security/commit/0c3754c
	 *
	 */
	public Jwt decode(String token) throws BadJwtException {
		Assert.notNull(token, "token is required");
		JWT jwt;

		try {
			jwt = JWTParser.parse(token);
		} catch (ParseException ex) {
			throw new BadJwtException("Error initializing JWT decoder: " + ex.getMessage());
		}
		final Jwt verifiedToken = verifyToken(jwt);
		postValidationActions.forEach(action -> action.perform(verifiedToken));
		return verifiedToken;
	}

	public void setTokenInfoExtractor(TokenInfoExtractor tokenInfoExtractor) {
		this.tokenInfoExtractor = tokenInfoExtractor;
	}

	public void setRestOperations(RestOperations restOperations) {
		this.restOperations = restOperations;
	}

	private Jwt verifyToken(JWT jwt) {
		try {
			String jku = tokenInfoExtractor.getJku(jwt);
			String kid = tokenInfoExtractor.getKid(jwt);
			String uaaDomain = tokenInfoExtractor.getUaaDomain(jwt);
			return verifyToken(jwt.getParsedString(), jku, kid, uaaDomain);
		} catch (BadJwtException e) {
			if (e.getMessage().contains("Couldn't retrieve remote JWK set")
					|| e.getMessage().contains("Cannot verify with online token key, uaadomain is")) {
				logger.debug(e.getMessage());
				return tryToVerifyWithVerificationKey(jwt.getParsedString(), e);
			} else {
				throw e;
			}
		}
	}

	private Jwt verifyToken(String token, String jku, String kid, String uaaDomain) {
		try {
			canVerifyWithKey(jku, kid, uaaDomain);
			validateJku(jku, uaaDomain);
			return verifyWithKey(token, jku, kid);
		} catch (JwtValidationException ex) {
			throw ex;
		} catch (JwtException ex) {
			throw new BadJwtException("JWT verification failed: " + ex.getMessage());
		}
	}

	private void canVerifyWithKey(String jku, String kid, String uaadomain) {
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

		throw new BadJwtException(String.format("Cannot verify with online token key, %s is null",
				String.join(", ", nullParams)));
	}

	private void validateJku(String jku, String uaadomain) {
		try {
			URI jkuUri = new URI(jku);
			if (jkuUri.getHost() == null) {
				throw new BadJwtException("JKU of token is not valid");
			} else if (!jkuUri.getHost().endsWith(uaadomain)) {
				logger.warn("Error: Do not trust jku '{}' because it does not match uaa domain '{}'.",
						jku, uaadomain);
				throw new BadJwtException("Do not trust 'jku' token header.");
			} else if (!jkuUri.getPath().endsWith("token_keys") || hasText(jkuUri.getQuery())
					|| hasText(jkuUri.getFragment())) {
				logger.warn("Error: Do not trust jku '{}' because it contains invalid path, query or fragment.", jku);
				throw new BadJwtException("Jwt token does not contain a valid 'jku' header parameter: " + jkuUri);
			}
		} catch (URISyntaxException e) {
			throw new BadJwtException("JKU of token header is not valid");
		}
	}

	@java.lang.SuppressWarnings("squid:S2259")
	private Jwt verifyWithKey(String token, String jku, String kid) {
		String cacheKey = jku + kid;
		JwtDecoder decoder = cache.get(cacheKey, k -> this.getDecoder(jku));
		return decoder.decode(token);
	}

	private JwtDecoder getDecoder(String jku) {
		Cache jwkSetCache = new ConcurrentMapCache("jwkSetCache", Caffeine.newBuilder()
				.expireAfterWrite(this.cacheValidityInSeconds)
				.maximumSize(this.cacheSize)
				.build().asMap(), false);
		JwkSetUriJwtDecoderBuilder jwkSetUriJwtDecoderBuilder = NimbusJwtDecoder
				.withJwkSetUri(jku)
				.cache(jwkSetCache);
		if (restOperations != null) {
			jwkSetUriJwtDecoderBuilder.restOperations(restOperations);
		}
		NimbusJwtDecoder jwtDecoder = jwkSetUriJwtDecoderBuilder.build();
		jwtDecoder.setJwtValidator(tokenValidators);
		return jwtDecoder;
	}

	private Jwt tryToVerifyWithVerificationKey(String token, JwtException verificationException) {
		logger.debug("Falling back to token validation with verificationkey");
		String verificationKey = xsuaaServiceConfiguration.getVerificationKey();
		if (!hasText(verificationKey)) {
			throw verificationException;
		}
		return verifyWithVerificationKey(token, verificationKey);
	}

	private Jwt verifyWithVerificationKey(String token, String verificationKey) {
		try {
			RSAPublicKey rsaPublicKey = createPublicKey(verificationKey);
			NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
			decoder.setJwtValidator(tokenValidators);
			return decoder.decode(token);
		} catch (NoSuchAlgorithmException | IllegalArgumentException | InvalidKeySpecException | BadJwtException e) {
			logger.debug("Jwt signature validation with fallback verificationkey failed: {}", e.getMessage());
			throw new BadJwtException("Jwt validation with fallback verificationkey failed");
		}
	}

	private static String extractKey(String pemEncodedKey) {
		return pemEncodedKey
				.replace("\n", "")
				.replace("\\n", "")
				.replace("\r", "")
				.replace("\\r", "")
				.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "");
	}

	private RSAPublicKey createPublicKey(String pemEncodedPublicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		logger.debug("verificationkey={}", pemEncodedPublicKey);
		String key = extractKey(pemEncodedPublicKey);
		logger.debug("RSA public key n+e={}", key);
		byte[] decodedKey = Base64.getDecoder().decode(key);
		X509EncodedKeySpec specX509 = new X509EncodedKeySpec(decodedKey);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPublicKey rsaPublicKeyX509 = (RSAPublicKey) keyFactory.generatePublic(specX509);
		logger.debug("parsed RSA e={}, n={}", rsaPublicKeyX509.getPublicExponent(), rsaPublicKeyX509.getModulus());
		return rsaPublicKeyX509;
	}

}
