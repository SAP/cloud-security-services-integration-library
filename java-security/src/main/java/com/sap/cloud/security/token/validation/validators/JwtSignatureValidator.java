package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.TokenClaims.*;
import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.jwk.JsonWebKey.*;
import static com.sap.cloud.security.xsuaa.jwk.JsonWebKeyConstants.*;
import static java.nio.charset.StandardCharsets.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Pattern;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

import com.sap.cloud.security.xsuaa.client.DefaultOidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.OAuth2TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.client.OidcConfigurationServiceWithCache;
import com.sap.cloud.security.xsuaa.jwk.JsonWebKeyImpl;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;

/**
 * Validates whether the jwt was signed with the public key of the trust-worthy
 * identity service. <br>
 * - asks the token key service for a set of (cached) json web token keys.<br>
 * - creates a PublicKey for the json web key with the respective id and type.
 * <br>
 * - checks whether the jwt is unchanged and signed with a private key that
 * matches the PublicKey.
 */
public class JwtSignatureValidator implements Validator<Token> {
	private final OAuth2TokenKeyServiceWithCache tokenKeyService;
	private final OidcConfigurationServiceWithCache oidcConfigurationService;
	private OAuth2ServiceConfiguration configuration;

	public JwtSignatureValidator(OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		assertNotNull(tokenKeyService, "tokenKeyService must not be null.");
		assertNotNull(tokenKeyService, "oidcConfigurationService must not be null.");

		this.tokenKeyService = tokenKeyService;
		this.oidcConfigurationService = oidcConfigurationService;
	}

	public JwtSignatureValidator withOAuth2Configuration(OAuth2ServiceConfiguration configuration) {
		this.configuration = configuration;
		return this;
	}

	@Override
	public ValidationResult validate(Token token) {
		String jwksUri;

		try {
			jwksUri = getOrRequestJwksUri(token);
			String fallbackPublicKey = null;
			if(configuration != null && configuration.hasProperty("verificationkey")) {
				fallbackPublicKey = configuration.getProperty("verificationkey");
			}
			return validate(token.getAccessToken(),
					token.getHeaderParameterAsString(ALGORITHM_PARAMETER_NAME),
					token.getHeaderParameterAsString(KEY_ID_PARAMETER_NAME),
					jwksUri,
					fallbackPublicKey);
		} catch (OAuth2ServiceException | IllegalArgumentException e) {
			return createInvalid("Error occurred during jwks uri determination: {}.", e.getMessage());
		}
	}

	// for testing
	ValidationResult validate(String token, String tokenAlgorithm, @Nullable String tokenKeyId, String tokenKeysUrl, String fallbackPublicKey) {
		assertHasText(token, "token must not be null or empty.");
		assertHasText(tokenKeysUrl, "tokenKeysUrl must not be null or empty.");

		return Validation.getInstance().validate(tokenKeyService, token, tokenAlgorithm, tokenKeyId,
				URI.create(tokenKeysUrl), fallbackPublicKey);
	}

	@Nonnull
	private String getOrRequestJwksUri(Token token) throws OAuth2ServiceException, IllegalArgumentException {
		if (token.hasHeaderParameter(KEYS_URL_PARAMETER_NAME)) {
			return token.getHeaderParameterAsString(KEYS_URL_PARAMETER_NAME);
		}
		if (token.hasClaim(ISSUER)) {
			URI discoveryUri = DefaultOidcConfigurationService.getDiscoveryEndpointUri(token.getClaimAsString(ISSUER));
			return oidcConfigurationService
					.getOrRetrieveEndpoints(discoveryUri)
					.getJwksUri().toString();
		}
		throw new IllegalArgumentException(
				"Token signature can not be validated as jwks uri can not be determined: Token does neither provide 'jku' header nor 'issuer' claim.");
	}

	private static class Validation {
		JwtSignatureAlgorithm jwtSignatureAlgorithm;
		PublicKey publicKey;
		Signature publicSignature;

		private Validation() {
		}

		static Validation getInstance() {
			return new Validation();
		}

		public ValidationResult validate(OAuth2TokenKeyServiceWithCache tokenKeyService, String token,
				String tokenAlgorithm,
				@Nullable String tokenKeyId, URI tokenKeysUrl, String fallbackPublicKey) {
			ValidationResult validationResult;

			validationResult = setJwtAlgorithm(tokenAlgorithm);
			if (validationResult.isErroneous()) {
				return validationResult;
			}

			String keyId = tokenKeyId != null ? tokenKeyId : DEFAULT_KEY_ID;
			validationResult = setPublicKey(tokenKeyService, keyId, tokenKeysUrl);
			if (validationResult.isErroneous()) {
				if (fallbackPublicKey != null) {
					try {
						this.publicKey = JsonWebKeyImpl.createPublicKeyFromPemEncodedPublicKey(
								JwtSignatureAlgorithm.RS256, fallbackPublicKey);
					} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
						return createInvalid(
								"Error occurred during signature validation: ({}). Fallback with configured verificationkey was not successful.",
								e.getMessage());
					}
				} else {
					return validationResult;
				}
			}
			validationResult = setPublicSignatureForKeyType();
			if (validationResult.isErroneous()) {
				return validationResult;
			}

			return validateTokenSignature(token, publicKey, publicSignature);
		}

		private ValidationResult setJwtAlgorithm(String tokenAlgorithm) {
			if (tokenAlgorithm != null) {
				jwtSignatureAlgorithm = JwtSignatureAlgorithm.fromValue(tokenAlgorithm);
				if (jwtSignatureAlgorithm != null) {
					return createValid();
				}
			}
			return createInvalid("Jwt token with signature algorithm '{}' can not be verified.", tokenAlgorithm);
		}

		private ValidationResult setPublicKey(OAuth2TokenKeyServiceWithCache tokenKeyService, String keyId,
				URI keyUri) {
			try {
				this.publicKey = tokenKeyService.getPublicKey(jwtSignatureAlgorithm, keyId, keyUri);
			} catch (OAuth2ServiceException e) {
				return createInvalid("Error retrieving Json Web Keys from Identity Service: {}.", e.getMessage());
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				return createInvalid("Error creating PublicKey from Json Web Key received from {}: {}.",
						keyUri, e.getMessage());
			}
			if (this.publicKey == null) {
				return createInvalid(
						"There is no Json Web Token Key with keyId '{}' and type '{}' to prove the identity of the Jwt.",
						keyId, jwtSignatureAlgorithm.type());
			}
			return createValid();
		}

		private ValidationResult setPublicSignatureForKeyType() {
			try {
				publicSignature = Signature.getInstance(jwtSignatureAlgorithm.javaSignature());
				return createValid();
			} catch (NoSuchAlgorithmException e) {
				// should never happen
			}
			return createInvalid("Jwt token with signature algorithm '{}' can not be verified.",
					jwtSignatureAlgorithm.javaSignature());
		}

		private static final Pattern DOT = Pattern.compile("\\.", 0);

		static ValidationResult validateTokenSignature(String token, PublicKey publicKey, Signature publicSignature) {
			String[] tokenHeaderPayloadSignature = DOT.split(token);
			if (tokenHeaderPayloadSignature.length != 3) {
				return createInvalid("Jwt token does not consist of 'header'.'payload'.'signature'.");
			}
			String headerAndPayload = new StringBuilder(tokenHeaderPayloadSignature[0]).append(".")
					.append(tokenHeaderPayloadSignature[1]).toString();
			try {
				publicSignature.initVerify(publicKey);
				publicSignature.update(headerAndPayload.getBytes(UTF_8)); // provide data

				byte[] decodedSignatureBytes = Base64.getUrlDecoder().decode(tokenHeaderPayloadSignature[2]);

				if (publicSignature.verify(decodedSignatureBytes)) {
					return createValid();
				}
				return createInvalid(
						"Signature of Jwt Token is not valid: the identity provided by the JSON Web Token Key can not be verified.");
			} catch (Exception e) {
				return createInvalid("Error occurred during Json Web Signature Validation: {}.", e.getMessage());
			}
		}
	}

}
