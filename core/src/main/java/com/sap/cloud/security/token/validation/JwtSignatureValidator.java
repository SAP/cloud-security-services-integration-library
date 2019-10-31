package com.sap.cloud.security.token.validation;

import static java.nio.charset.StandardCharsets.*;

import javax.annotation.Nullable;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.core.Assertions;
import com.sap.cloud.security.core.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.client.XsuaaDefaultEndpoints;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKey;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;

public class JwtSignatureValidator implements Validator<DecodedJwt> {
	private Map<String, PublicKey> keyCache = new HashMap<>();
	private OAuth2ServiceConfiguration serviceConfiguration;
	private OAuth2TokenKeyService tokenKeyService;
	private OAuth2ServiceEndpointsProvider tokenUrlProvider;
	private static Logger LOGGER = LoggerFactory.getLogger(JwtSignatureValidator.class);

	public JwtSignatureValidator(OAuth2ServiceConfiguration xsuaaServiceConfiguration, OAuth2TokenKeyService tokenKeyService) {
		Assertions.assertNotNull(xsuaaServiceConfiguration, "'xsuaaServiceConfiguration' is required");
		Assertions.assertNotNull(tokenKeyService, "'tokenKeyService' is required");
		this.serviceConfiguration = xsuaaServiceConfiguration;
		this.tokenKeyService = tokenKeyService;
		this.tokenUrlProvider = new XsuaaDefaultEndpoints(serviceConfiguration.getUaaUrl());
	}

	@Override
	public ValidationResult validate(DecodedJwt decodedJwt) {
		String kid = "key-id-1"; //TODO parse from JSON Header e.g. decodedJwt.getHeader().getKeyId()
		String alg = "RS256"; //TODO parse from JSON Header e.g. decodedJwt.getHeader().getAlgorithm()
		String jku = "https://authentication.stagingaws.hanavlab.ondemand.com/token_keys"; //TODO parse from JSON Header e.g. decodedJwt.getHeader().getJsonKeyUrl()

		return validate(decodedJwt.getEncodedToken(), kid, alg,jku);
	}

	public ValidationResult validate(String token, String tokenKeyId, String tokenAlgorithm, String tokenKeyUrl) {
		// TODO validate jku by validating with uaaDomain

		PublicKey publicKey = getPublicKey(tokenKeyId, tokenKeyUrl);
		if (publicKey == null) {
			return ValidationResults.createInvalid("There is no JSON Web Token Key to prove the identity of the JWT.");
		}
		try {
			if(!isJwtSignatureValid(token, tokenAlgorithm, publicKey)) {
				return ValidationResults.createInvalid("Signature verification failed.");
			}
		} catch (Exception e) {
			LOGGER.error("Error during JSON Web Signature could not be verified.", e);
			return ValidationResults.createInvalid(e.getMessage());
		}
		return ValidationResults.createValid();
	}

	@Nullable
	private PublicKey getPublicKey(String kid, String jku) {
		PublicKey publicKey = lookupCache(kid); // TODO kid + kty?
		if (publicKey == null) {
			try {
				JSONWebKeySet jwks = tokenKeyService.retrieveTokenKeys(tokenUrlProvider.getJwksUri());
				JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, kid);  //TODO kid + kty?
				publicKey = createPublicKeyFromString(jwk.getType(), jwk.getPublicKey());
				keyCache.put(kid, publicKey); //TODO kid + kty?
			} catch (OAuth2ServiceException e) {
				LOGGER.error("Error retrieving JSON Web Keys from Identity Service ({}).", tokenUrlProvider.getJwksUri(), e);
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				LOGGER.error("Error creating PublicKey from JSON Web Key received from Identity Service ({}).", tokenUrlProvider.getAuthorizeEndpoint(), e);
			}
		}
		return publicKey;
	}

	private PublicKey lookupCache(String kid) {
		return keyCache.get(kid);
	}

	private PublicKey createPublicKeyFromString(JSONWebKey.Type webKeyType, String publicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		if(webKeyType != JSONWebKey.Type.RSA) {
			throw new IllegalStateException("JWT token with web key type " + webKeyType + " can not be verified.");
		}
		KeyFactory keyFactory = KeyFactory.getInstance(webKeyType.value()); // "RSA"

		byte[] decodedKeyBytes = Base64.getDecoder().decode(publicKey);

		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(decodedKeyBytes);
		return keyFactory.generatePublic(keySpecX509);
	}


	private boolean isJwtSignatureValid(String token, String tokenAlgorithm, PublicKey publicKey) throws
			SignatureException, InvalidKeyException, NoSuchAlgorithmException {
		if(!"RS256".equalsIgnoreCase(tokenAlgorithm)) {
			throw new IllegalStateException("JWT token with signature algorithm " + tokenAlgorithm + " can not be verified.");
		}
		String[] tokenHeaderPayloadSignature = token.split(Pattern.quote("."));
		if(tokenHeaderPayloadSignature.length != 3) {
			throw new IllegalArgumentException("JWT token does not consist of 'header'.'payload'.'signature'.");
		}
		String headerAndPayload = new StringBuilder( tokenHeaderPayloadSignature[0]).append( "." ).append(tokenHeaderPayloadSignature[1]).toString();

		Signature publicSignature = Signature.getInstance("SHA256withRSA"); //RSASSA-PKCS1-v1_5 using SHA-256 according to https://tools.ietf.org/html/rfc7518#section-3
		publicSignature.initVerify(publicKey);
		publicSignature.update(headerAndPayload.getBytes( UTF_8)); // provide data

		byte[] decodedSignatureBytes = Base64.getUrlDecoder().decode(tokenHeaderPayloadSignature[2]);

		boolean isSignatureValid = publicSignature.verify(decodedSignatureBytes);
		if(!isSignatureValid) {
			LOGGER.error("Signature of JWT Token is not valid: the identity provided by the JSON Web Token Key can not be verified");
		}
		return isSignatureValid;
	}
}
