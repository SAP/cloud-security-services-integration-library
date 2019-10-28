package com.sap.cloud.security.token.validation;

import com.sap.cloud.security.core.Assertions;
import com.sap.cloud.security.core.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyService;
import com.sap.cloud.security.xsuaa.jwt.DecodedJwt;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKey;
import com.sap.cloud.security.xsuaa.jwt.JSONWebKeySet;

import java.net.URI;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static java.nio.charset.StandardCharsets.UTF_8;

public class OAuth2TokenSignatureValidator implements Validator<DecodedJwt> {
	Map<String, PublicKey> keyCache = new HashMap<>();
	OAuth2ServiceConfiguration serviceConfiguration;
	OAuth2TokenKeyService tokenKeyService;

	public OAuth2TokenSignatureValidator(OAuth2ServiceConfiguration xsuaaServiceConfiguration, OAuth2TokenKeyService tokenKeyService) {
		Assertions.assertNotNull(xsuaaServiceConfiguration, "'xsuaaServiceConfiguration' is required");
		Assertions.assertNotNull(tokenKeyService, "'tokenKeyService' is required");
		this.serviceConfiguration = xsuaaServiceConfiguration;
		this.tokenKeyService = tokenKeyService;
	}

	@Override
	public ValidationResult validate(DecodedJwt token) { // TODO Decoded JWT
		String kid = "key-id-1"; //TODO parse from JSON Header
		String kty = "RS256"; //TODO parse from JSON Header
		String jku = "https://authentication.stagingaws.hanavlab.ondemand.com/token_keys"; //TODO parse from JSON Header

		PublicKey publicKey = lookupCache(kid); // kid + alg?
		// TODO validate jku by validating with uaaDomain
		if (publicKey == null) {
			try {
				JSONWebKeySet jwks = tokenKeyService.retrieveTokenKeys(URI.create(jku));
				publicKey = createPublicKey(jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, kid));
			} catch (OAuth2ServiceException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				return ValidationResults.createInvalid(e.getMessage());
			}
		}
		try {
			return verify("RSA", token.getPayload(), token.getSignature(), publicKey);
		} catch (Exception e) {
			return ValidationResults.createInvalid(e.getMessage());
		}

	}

	private PublicKey lookupCache(String kid) {
		return keyCache.get(kid);
	}

	private PublicKey createPublicKey(JSONWebKey webKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
			KeyFactory keyFactory = KeyFactory.getInstance(webKey.getType().value()); // "RSA"

			X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(webKey.getPublicKey()));
			return keyFactory.generatePublic(keySpecX509);
		}


	private ValidationResult verify(String algorithm, String plainText, String signature, PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance("SHA256withRSA"); //"SHA256withRSA"
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes(UTF_8));

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		boolean isValid = publicSignature.verify(signatureBytes);
		if (isValid) {
			return ValidationResults.createValid();
		} else {
			return ValidationResults.createInvalid("Signature verification failed!");
		}
	}
}
