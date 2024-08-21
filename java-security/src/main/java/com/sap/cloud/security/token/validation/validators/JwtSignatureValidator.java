/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.ALG_PARAMETER_NAME;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Validates the signature of the JWT.<br> - retrieves the public key used for validation via the tokenKeyService.<br> -
 * checks whether the signature section of the JWT is a valid signature for the header and payload sections for this
 * public key.
 */
abstract class JwtSignatureValidator implements Validator<Token> {
	protected final OAuth2TokenKeyServiceWithCache tokenKeyService;
	protected final OidcConfigurationServiceWithCache oidcConfigurationService;
	protected final OAuth2ServiceConfiguration configuration;

	JwtSignatureValidator(OAuth2ServiceConfiguration configuration, OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		assertNotNull(configuration, "JwtSignatureValidator requires configuration.");
		assertNotNull(tokenKeyService, "JwtSignatureValidator requires a tokenKeyService.");
		assertNotNull(oidcConfigurationService, "JwtSignatureValidator requires a oidcConfigurationService.");

		this.configuration = configuration;
		this.tokenKeyService = tokenKeyService;
		this.oidcConfigurationService = oidcConfigurationService;
	}

	@Override
	public ValidationResult validate(Token token) {
		if (token.getTokenValue() == null) {
			return createInvalid("JWT token validation failed because token content was null.");
		}

		JwtSignatureAlgorithm algorithm = JwtSignatureAlgorithm.RS256;
		if (token.hasHeaderParameter(ALG_PARAMETER_NAME)) {
			String algHeader = token.getHeaderParameterAsString(ALG_PARAMETER_NAME);
			algorithm = JwtSignatureAlgorithm.fromValue(algHeader);
			if (algorithm == null) {
				return createInvalid(
						"JWT token validation with signature algorithm '" + algHeader + "' is not supported.");
			}
		}

		PublicKey publicKey;
		try {
			publicKey = getPublicKey(token, algorithm);
		} catch (OAuth2ServiceException e) {
			return createInvalid("Token signature can not be validated because JWKS could not be fetched: {}",
					e.getMessage());
		} catch (IllegalArgumentException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			return createInvalid("Token signature can not be validated because: {}", e.getMessage());
		}

		if (publicKey == null) {
			return createInvalid("Token signature can not be validated because JWKS was empty.");
		}

		return validateSignature(token, publicKey, algorithm);
	}

	/**
	 * Service-specific implementation for the retrieval of the public key, e.g. via URL from JKU header (XSUAA) or OIDC
	 * .well-known endpoint (IAS)
	 */
	protected abstract PublicKey getPublicKey(Token token, JwtSignatureAlgorithm algorithm)
			throws OAuth2ServiceException, InvalidKeySpecException, NoSuchAlgorithmException;

	protected ValidationResult validateSignature(Token token, PublicKey publicKey, JwtSignatureAlgorithm algorithm) {
		Signature publicSignature;
		try {
			publicSignature = Signature.getInstance(algorithm.javaSignature());
		} catch (NoSuchAlgorithmException e) {
			return createInvalid(
					"Token signature can not be validated because implementation of algorithm could not be found: {}",
					e.getMessage());
		}

		String[] tokenSections = token.getTokenValue().split("\\.");
		if (tokenSections.length != 3) {
			return createInvalid("Jwt token does not consist of three sections: 'header'.'payload'.'signature'.");
		}

		String headerAndPayload = tokenSections[0] + "." + tokenSections[1];
		String signature = tokenSections[2];
		try {
			publicSignature.initVerify(publicKey);
			publicSignature.update(headerAndPayload.getBytes(UTF_8));

			byte[] decodedSignatureBytes = Base64.getUrlDecoder().decode(signature);
			if (publicSignature.verify(decodedSignatureBytes)) {
				return createValid();
			}

			return createInvalid(
					"Signature of Jwt Token is not valid: the identity provided by the JSON Web Token Key can not be trusted (Signature: {}).",
					signature);
		} catch (Exception e) {
			return createInvalid("Unexpected Error occurred during Json Web Signature Validation: {}.", e.getMessage());
		}
	}
}
