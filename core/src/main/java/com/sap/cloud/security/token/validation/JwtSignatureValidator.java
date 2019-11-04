package com.sap.cloud.security.token.validation;

import static com.sap.cloud.security.core.Assertions.*;
import static com.sap.cloud.security.xsuaa.jwt.JSONWebKeyConstants.*;
import static java.nio.charset.StandardCharsets.*;

import javax.annotation.Nullable;

import java.net.URI;
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

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceEndpointsProvider;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKey;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;

public class JwtSignatureValidator implements Validator<Token> {
	private Map<String, PublicKey> keyCache = new HashMap<>();
	private OAuth2TokenKeyService tokenKeyService;
	private URI jwksUri;
	private static Logger LOGGER = LoggerFactory.getLogger(JwtSignatureValidator.class);

	public JwtSignatureValidator(OAuth2TokenKeyService tokenKeyService, OAuth2ServiceEndpointsProvider endpointsProvider) {
		this(tokenKeyService, endpointsProvider.getJwksUri());
	}

	public JwtSignatureValidator(OAuth2TokenKeyService tokenKeyService, URI jwksUri) {
		assertNotNull(tokenKeyService, "tokenKeyService must not be null.");
		assertNotNull(jwksUri, "jwksUri must not be null.");

		this.tokenKeyService = tokenKeyService;
		this.jwksUri = jwksUri;
	}

	@Override
	public ValidationResult validate(Token token) {
		return validate(token.getAppToken(),
				token.getHeaderValueAsString(ALGORITHM_PARAMETER_NAME),
				token.getHeaderValueAsString(KEY_ID_PARAMETER_NAME));
	}

	public ValidationResult validate(String token, String tokenAlgorithm, @Nullable String tokenKeyId) {
		assertNotEmpty(token, "token must not be null / empty string.");
		assertNotEmpty(tokenAlgorithm, "tokenAlgorithm must not be null / empty string.");

		/*if(!isTokenKeyUrlValid(tokenKeyUrl, serviceConfiguration.getUaaDomain())) {
				return ValidationResults.createInvalid("JKU of token header is not trusted.");
		}*/

		PublicKey publicKey = getPublicKey(tokenKeyId != null ? tokenKeyId : JSONWebKey.DEFAULT_KEY_ID);
		if (publicKey == null) {
			return ValidationResults.createInvalid("There is no JSON Web Token Key to prove the identity of the JWT.");
		}
		try {
			if(!isTokenSignatureValid(token, tokenAlgorithm, publicKey)) {
				return ValidationResults.createInvalid("Signature verification failed.");
			}
		} catch (Exception e) {
			LOGGER.error("Error during JSON Web Signature could not be verified.", e);
			return ValidationResults.createInvalid(e.getMessage());
		}
		return ValidationResults.createValid();
	}

	@Nullable
	private PublicKey getPublicKey(String keyId) {
		PublicKey publicKey = lookupCache(keyId); // TODO kid + kty?
		if (publicKey == null) {
			try {
				JSONWebKeySet jwks = tokenKeyService.retrieveTokenKeys(jwksUri);
				JSONWebKey jwk = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, keyId); // TODO what if kid is not supported?
				if(jwk != null && jwk.getPublicKey() != null) {
					publicKey = createPublicKeyFromString(jwk.getType(), jwk.getPublicKey());
					keyCache.put(keyId, publicKey); //TODO kid + kty?
				}
			} catch (OAuth2ServiceException e) {
				LOGGER.warn("Error retrieving JSON Web Keys from Identity Service ({}).", jwksUri, e);
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				LOGGER.warn("Error creating PublicKey from JSON Web Key received from Identity Service ({}).", jwksUri, e);
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

	private boolean isTokenSignatureValid(String token, String tokenAlgorithm, PublicKey publicKey) throws
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
			LOGGER.warn("Error: Signature of JWT Token is not valid: the identity provided by the JSON Web Token Key can not be verified");
		}
		return isSignatureValid;
	}

	// TODO move to XsuaaIssuerValidator
	/*private boolean isTokenKeyUrlValid(String jku, String identityServiceDomain) {
		URI jkuUri;
		try {
			jkuUri = new URI(jku);
		} catch (URISyntaxException e) {
			LOGGER.warn("Error: JKU of token header '{}' is not a valid URI", jku);
			return false;
		}
		if(!jkuUri.getHost().endsWith(identityServiceDomain)) {
			LOGGER.warn("Error: Do not trust jku '{}' because it does not match uaa domain '{}'",
					jku, identityServiceDomain);
			return false;
		}
		return true;
	}*/
}
