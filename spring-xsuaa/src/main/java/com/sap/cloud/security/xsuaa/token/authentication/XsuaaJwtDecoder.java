package com.sap.cloud.security.xsuaa.token.authentication;

import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_JKU;
import static com.sap.cloud.security.xsuaa.token.TokenClaims.CLAIM_KID;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.sap.cloud.security.xsuaa.XsuaaServiceConfiguration;
import org.springframework.web.client.RestOperations;

public class XsuaaJwtDecoder implements JwtDecoder {
	private final Logger logger = LoggerFactory.getLogger(getClass());
	private final XsuaaServiceConfiguration xsuaaServiceConfiguration;

	Cache<String, JwtDecoder> cache;
	private OAuth2TokenValidator<Jwt> tokenValidators;
	private Collection<PostValidationAction> postValidationActions;
	private TokenInfoExtractor tokenInfoExtractor;
	private RestOperations restOperations;

	XsuaaJwtDecoder(XsuaaServiceConfiguration xsuaaServiceConfiguration, int cacheValidityInSeconds, int cacheSize,
			OAuth2TokenValidator<Jwt> tokenValidators, Collection<PostValidationAction> postValidationActions) {

		this.cache = Caffeine.newBuilder().expireAfterWrite(cacheValidityInSeconds, TimeUnit.SECONDS)
				.maximumSize(cacheSize)
				.build();
		this.tokenValidators = tokenValidators;
		this.xsuaaServiceConfiguration = xsuaaServiceConfiguration;

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
		this.postValidationActions = postValidationActions != null ? postValidationActions : Collections.emptyList();
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
			return verifyTokenOnline(jwt.getParsedString(), jku, kid, uaaDomain);
		} catch (JwtException e) {
			return tryToVerifyWithOfflineKey(jwt.getParsedString(), e);
		}
	}

	private Jwt verifyTokenOnline(String token, String jku, String kid, String uaaDomain) {
		try {
			canVerifyWithOnlineKey(jku, kid, uaaDomain);
			validateJKU(jku, uaaDomain);
			Jwt verifiedToken = verifyWithOnlineKey(token, jku, kid);

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
		NimbusJwtDecoder.JwkSetUriJwtDecoderBuilder jwkSetUriJwtDecoderBuilder = NimbusJwtDecoder.withJwkSetUri(jku);
		if (restOperations != null) {
			jwkSetUriJwtDecoderBuilder.restOperations(restOperations);
		}
		NimbusJwtDecoder jwtDecoder = jwkSetUriJwtDecoderBuilder.build();
		jwtDecoder.setJwtValidator(tokenValidators);
		return jwtDecoder;
	}

	private Jwt tryToVerifyWithOfflineKey(String token, JwtException onlineVerificationException) {
		String verificationKey = xsuaaServiceConfiguration.getVerificationKey();
		if (verificationKey == null || verificationKey.isEmpty()) {
			throw onlineVerificationException;
		}
		return verifyWithOfflineKey(token, verificationKey);
	}

	private Jwt verifyWithOfflineKey(String token, String verificationKey) {
		try {
			RSAPublicKey verficationKey = createPublicKey(verificationKey);
			NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(verficationKey).build();
			decoder.setJwtValidator(tokenValidators);
			return decoder.decode(token);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new JwtException(e.getMessage());
		}
	}

	// TODO: move this code into token-client?
	private static String convertPEMKey(String pemEncodedKey) {
		String key = pemEncodedKey;
		key = key.replace("-----BEGIN PUBLIC KEY-----", "");
		key = key.replace("-----END PUBLIC KEY-----", "");
		return key;
	}

	private RSAPublicKey createPublicKey(String pemEncodedPublicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		byte[] decodedKey = Base64.getDecoder().decode(convertPEMKey(pemEncodedPublicKey));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
		return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
	}

}
