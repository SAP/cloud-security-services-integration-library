package com.sap.cloud.security.token.validation.validators;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static com.sap.cloud.security.xsuaa.jwk.JsonWebKey.*;
import static com.sap.cloud.security.xsuaa.jwk.JsonWebKeyConstants.*;
import static java.nio.charset.StandardCharsets.*;

import javax.annotation.Nullable;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Pattern;

import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;

import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;
import com.sap.cloud.security.xsuaa.client.TokenKeyServiceWithCache;
import com.sap.cloud.security.xsuaa.jwt.JwtSignatureAlgorithm;

/**
 * Validates whether the jwt was signed with the public key of the trust-worthy
 * identity service. - asks the token key service for a set of (cached) json web
 * token keys. - creates a PublicKey for the json web key with the respective id
 * and type. - checks whether the jwt is unchanged and signed with a private key
 * that matches the PublicKey.
 */
public class JwtSignatureValidator implements Validator<Token> {
	private final TokenKeyServiceWithCache tokenKeyService;

	public JwtSignatureValidator(TokenKeyServiceWithCache tokenKeyService) {
		assertNotNull(tokenKeyService, "tokenKeyService must not be null.");

		this.tokenKeyService = tokenKeyService;
	}

	@Override
	public ValidationResult validate(Token token) {

		return validate(token.getAccessToken(),
				token.getHeaderParameterAsString(ALGORITHM_PARAMETER_NAME),
				token.getHeaderParameterAsString(KEY_ID_PARAMETER_NAME),
				token.getHeaderParameterAsString(KEYS_URL_PARAMETER_NAME));
	}

	public ValidationResult validate(String token, String tokenAlgorithm, @Nullable String tokenKeyId,
			@Nullable String tokenKeysUrl) {
		assertHasText(token, "token must not be null or empty.");

		return Validation.getInstance().validate(tokenKeyService, token, tokenAlgorithm, tokenKeyId, tokenKeysUrl);
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

		public ValidationResult validate(TokenKeyServiceWithCache tokenKeyService, String token, String tokenAlgorithm,
				@Nullable String tokenKeyId, @Nullable String tokenKeysUrl) {
			assertHasText(token, "token must not be null or empty.");

			ValidationResult validationResult;

			validationResult = setJwtAlgorithm(tokenAlgorithm);
			if (validationResult.isErroneous()) {
				return validationResult;
			}

			String keyId = tokenKeyId != null ? tokenKeyId : DEFAULT_KEY_ID;
			validationResult = setPublicKey(tokenKeyService, keyId, tokenKeysUrl);
			if (validationResult.isErroneous()) {
				return validationResult;
			}

			validationResult = setPublicSignatureForKeyType();
			if (validationResult.isErroneous()) {
				return validationResult;
			}

			return isTokenSignatureValid(token);
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

		private ValidationResult setPublicKey(TokenKeyServiceWithCache tokenKeyService, String keyId,
				String keyUri) {
			try {
				this.publicKey = tokenKeyService.getPublicKey(jwtSignatureAlgorithm, keyId, keyUri);
			} catch (OAuth2ServiceException e) {
				return createInvalid("Error retrieving Json Web Keys from Identity Service: {}.", e.getMessage());
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				return createInvalid("Error creating PublicKey from Json Web Key received from {}: {}.",
						keyUri != null ? keyUri : tokenKeyService.getDefaultJwksUri(), e.getMessage());
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

		private ValidationResult isTokenSignatureValid(String token) {
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
