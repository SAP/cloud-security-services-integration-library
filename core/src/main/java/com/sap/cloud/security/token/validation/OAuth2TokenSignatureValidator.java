package com.sap.cloud.security.token.validation;

import static java.nio.charset.StandardCharsets.*;

import javax.annotation.Nullable;
import javax.xml.bind.DatatypeConverter;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
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
import com.sap.cloud.security.xsuaa.jwt.JSONWebKey;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;

public class OAuth2TokenSignatureValidator implements Validator<String> {
	private Map<String, PublicKey> keyCache = new HashMap<>();
	private OAuth2ServiceConfiguration serviceConfiguration;
	private OAuth2TokenKeyService tokenKeyService;
	private OAuth2ServiceEndpointsProvider tokenUrlProvider;
	private static Logger LOGGER = LoggerFactory.getLogger(OAuth2TokenSignatureValidator.class);

	public OAuth2TokenSignatureValidator(OAuth2ServiceConfiguration xsuaaServiceConfiguration, OAuth2TokenKeyService tokenKeyService) {
		Assertions.assertNotNull(xsuaaServiceConfiguration, "'xsuaaServiceConfiguration' is required");
		Assertions.assertNotNull(tokenKeyService, "'tokenKeyService' is required");
		this.serviceConfiguration = xsuaaServiceConfiguration;
		this.tokenKeyService = tokenKeyService;
		this.tokenUrlProvider = new XsuaaDefaultEndpoints(serviceConfiguration.getUaaUrl());
	}

	@Override
	public ValidationResult validate(String token) {
		// DecodedJwt decodedJwt = new Base64JwtDecoder().decode(token);
		String kid = "key-id-1"; //TODO parse from JSON Header e.g. decodedJwt.getHeader().getKeyId()
		String alg = "RS256"; //TODO parse from JSON Header e.g. decodedJwt.getHeader().getAlgorithm()
		String jku = "https://authentication.stagingaws.hanavlab.ondemand.com/token_keys"; //TODO parse from JSON Header e.g. decodedJwt.getHeader().getJsonKeyUrl()

		// TODO validate jku by validating with uaaDomain

		PublicKey publicKey = getPublicKey(kid, jku);
		if (publicKey == null) {
			return ValidationResults.createInvalid("There is no JSON Web Token Key to prove the identity of the JWT.");
		}
		try {
			return verifySignature(token, alg, publicKey);
		} catch (Exception e) {
			LOGGER.error("Error during JSON Web Signature could not be verified.", e);
			return ValidationResults.createInvalid(e.getMessage());
		}
	}

	@Nullable
	private PublicKey getPublicKey(String kid, String jku) {
		PublicKey publicKey = lookupCache(kid); // TODO kid + kty?
		if (publicKey == null) {
			try {
				JSONWebKeySet jwks = tokenKeyService.retrieveTokenKeys(tokenUrlProvider.getAuthorizeEndpoint()); // TODO
				JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, kid); // TODO check
				publicKey = createPublicKeyFromString(jwk.getType(), jwk.getPublicKey());
				keyCache.put(kid, publicKey); //TODO kid + kty
			} catch (OAuth2ServiceException e) {
				LOGGER.error("Error retrieving token keys from Identity Service ({}).", tokenUrlProvider.getAuthorizeEndpoint(), e);
			} catch (NoSuchAlgorithmException | UnsupportedEncodingException | InvalidKeySpecException e) {
				LOGGER.error("Error creating PublicKey from JSON Web Key received from Identity Service({}).", tokenUrlProvider.getAuthorizeEndpoint(), e);
			}
		}
		return publicKey;
	}

	private PublicKey lookupCache(String kid) {
		return keyCache.get(kid);
	}

	private PublicKey createPublicKeyFromString(JSONWebKey.Type webKeyType, String publicKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
		if(webKeyType != JSONWebKey.Type.RSA) {
			throw new IllegalStateException("JWT token with web key type " + webKeyType + " can not be verified.");
		}
		KeyFactory keyFactory = KeyFactory.getInstance(webKeyType.value()); // "RSA"

		byte[] keyBytes = DatatypeConverter.parseBase64Binary(
			new String(publicKey.getBytes(UTF_8.name()), UTF_8));

		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(keyBytes);
		return keyFactory.generatePublic(keySpecX509);
	}


	private ValidationResult verifySignature(String token, String algorithm, PublicKey publicKey) throws
			SignatureException, InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		if(!"RS256".equalsIgnoreCase(algorithm)) {
			throw new IllegalStateException("JWT token with signature algorithm " + algorithm + " can not be verified.");
		}
		String[] tokenHeaderPayloadSignature = token.split(Pattern.quote("."));
		if(tokenHeaderPayloadSignature.length != 3) {
			throw new IllegalArgumentException("JWT token does not consist of 'header'.'payload'.'signature'.");
		}
		String headerAndPayload = new StringBuilder( tokenHeaderPayloadSignature[0]).append( "." ).append(tokenHeaderPayloadSignature[1]).toString();

		Signature publicSignature = Signature.getInstance("SHA256withRSA"); //RSASSA-PKCS1-v1_5 using SHA-256 according to https://tools.ietf.org/html/rfc7518#section-3
		publicSignature.initVerify(publicKey);
		publicSignature.update(headerAndPayload.getBytes( UTF_8)); // provide data

		boolean isSignatureValid = publicSignature.verify(parseTokenSignature(tokenHeaderPayloadSignature[2]));
		if(!isSignatureValid) {
			LOGGER.error("Signature of JWT Token is not valid: the identity provided by the JSON Web Token Key can not be verified");
			return ValidationResults.createInvalid("Signature verification failed!");
		}
		return ValidationResults.createValid();
	}

	private static byte[] parseTokenSignature(final String signature) throws UnsupportedEncodingException {
		String tokenSignature = signature;
		int padding = 4 - tokenSignature.getBytes(UTF_8.name()).length % 4;
		if (padding != 4) {
			for (int i = 0; i < padding; ++i)
				tokenSignature += '=';
		}
		tokenSignature = tokenSignature.replaceAll("-", "+");
		tokenSignature = tokenSignature.replaceAll("_", "/");

		return DatatypeConverter.parseBase64Binary(
				new String(tokenSignature.getBytes(UTF_8.name()), UTF_8));
	}
}
