package com.sap.cloud.security.token.validation;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.URI;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.sap.cloud.security.core.Assertions;
import com.sap.cloud.security.core.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.client.OAuth2ServiceException;
import com.sap.cloud.security.token.client.OAuth2TokenKeyService;
import com.sap.cloud.security.token.jwt.DecodedJwt;
import com.sap.cloud.security.token.jwt.JSONWebKey;
import com.sap.cloud.security.token.jwt.JSONWebKeySet;

public class OAuth2TokenSignatureValidator { //TODO implement interface
	Map<String, PublicKey> keyCache = new HashMap<>();
	OAuth2ServiceConfiguration serviceConfiguration;
	OAuth2TokenKeyService tokenKeyService;

	public OAuth2TokenSignatureValidator(OAuth2ServiceConfiguration xsuaaServiceConfiguration, OAuth2TokenKeyService tokenKeyService) {
		Assertions.assertNotNull(xsuaaServiceConfiguration, "'xsuaaServiceConfiguration' is required");
		Assertions.assertNotNull(tokenKeyService, "'tokenKeyService' is required");
		this.serviceConfiguration = xsuaaServiceConfiguration;
		this.tokenKeyService = tokenKeyService;
	}

	public boolean validate(DecodedJwt token) { // TODO Decoded JWT
		String kid = "key-id-1"; //TODO parse from JSON Header
		String kty = "RS256"; //TODO parse from JSON Header
		String jku = "https://authentication.stagingaws.hanavlab.ondemand.com/token_keys"; //TODO parse from JSON Header

		PublicKey publicKey = lookupCache(kid); // kid + alg?
		// TODO validate jku by validating with uaaDomain
		if (publicKey == null) {
			try {
				JSONWebKeySet jwks = tokenKeyService.retrieveTokenKeys(URI.create(jku));
				publicKey = jwks.getKeyByTypeAndId(JSONWebKey.Type.RSA, kid).getPublicKey();
			} catch (OAuth2ServiceException e) {
				e.printStackTrace();
				return false;
			}
		}
		try {
			return verify("RSA", token.getPayload(), token.getSignature(), publicKey);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

	}

	private PublicKey lookupCache(String kid) {
		return keyCache.get(kid);
	}


	private static boolean verify(String algorithm, String plainText, String signature, PublicKey publicKey) throws Exception {
		Signature publicSignature = Signature.getInstance("SHA256withRSA"); //"SHA256withRSA"
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes(UTF_8));

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		return publicSignature.verify(signatureBytes);
	}
}
