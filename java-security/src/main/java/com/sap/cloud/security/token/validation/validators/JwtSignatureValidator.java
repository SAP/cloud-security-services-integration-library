/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.config.Service;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.client.DefaultOidcConfigurationService;
import com.sap.cloud.security.xsuaa.client.OAuth2ServiceException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.regex.Pattern;

import static com.sap.cloud.security.token.validation.ValidationResults.createInvalid;
import static com.sap.cloud.security.token.validation.ValidationResults.createValid;
import static com.sap.cloud.security.token.validation.validators.JsonWebKey.DEFAULT_KEY_ID;
import static com.sap.cloud.security.token.validation.validators.JsonWebKeyConstants.*;
import static com.sap.cloud.security.xsuaa.Assertions.assertHasText;
import static com.sap.cloud.security.xsuaa.Assertions.assertNotNull;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Validates whether the jwt was signed with the public key of the trust-worthy
 * identity service. <br>
 * - asks the token key service for a set of (cached) json web token keys.<br>
 * - creates a PublicKey for the json web key with the respective id and type.
 * <br>
 * - checks whether the jwt is unchanged and signed with a private key that
 * matches the PublicKey.
 */
class JwtSignatureValidator implements Validator<Token> {
	private final OAuth2TokenKeyServiceWithCache tokenKeyService;
	private final OidcConfigurationServiceWithCache oidcConfigurationService;
	private final OAuth2ServiceConfiguration configuration;
	private boolean isTenantIdCheckEnabled = true;

	JwtSignatureValidator(OAuth2ServiceConfiguration configuration, OAuth2TokenKeyServiceWithCache tokenKeyService,
			OidcConfigurationServiceWithCache oidcConfigurationService) {
		assertNotNull(configuration, "JwtSignatureValidator requires configuration.");
		assertNotNull(tokenKeyService, "JwtSignatureValidator requires a tokenKeyService.");
		assertNotNull(oidcConfigurationService, "JwtSignatureValidator requires a oidcConfigurationService.");

		this.configuration = configuration;
		this.tokenKeyService = tokenKeyService;
		this.oidcConfigurationService = oidcConfigurationService;
	}

	/**
	 * This method disables the tenant id check. In case Jwt issuer `iss` claim
	 * doesn't match with the `url` attribute from
	 * {@link OAuth2ServiceConfiguration)}, tenant-id (zid) claim needs to be
	 * present in token to ensure that the tenant belongs to this issuer.
	 * <p>
	 * Use with caution as it relaxes the validation rules! It is not recommended to
	 * disable this check for standard Identity service setup.
	 */
	void disableTenantIdCheck() {
		this.isTenantIdCheckEnabled = false;
	}

	@Override
	@SuppressWarnings("lgtm[java/dereferenced-value-may-be-null]")
	public ValidationResult validate(Token token) {
		String jwksUri;
		String keyId;
		String appTidForTokenKeys = null;
		String azpForTokenKeys = null;

		if (Service.IAS == configuration.getService()) {
			appTidForTokenKeys = token.getAppTid();
			if (isTenantIdCheckEnabled && !token.getIssuer().equals("" + configuration.getUrl())
					&& appTidForTokenKeys == null) {
				return createInvalid("Error occurred during signature validation: OIDC token must provide app_tid.");
			}
			azpForTokenKeys = token.getClaimAsString(TokenClaims.AUTHORIZATION_PARTY);
		}
		try {
			jwksUri = getOrRequestJwksUri(token);
			String fallbackPublicKey = null;
			if (configuration.hasProperty("verificationkey")) {
				fallbackPublicKey = configuration.getProperty("verificationkey");
			}
			keyId = getOrDefaultKeyId(token);
			return validate(token.getTokenValue(),
					getOrDefaultSignatureAlgorithm(token),
					keyId,
					jwksUri,
					fallbackPublicKey,
					appTidForTokenKeys,
					azpForTokenKeys);
		} catch (OAuth2ServiceException | IllegalArgumentException e) {
			return createInvalid("Error occurred during jwks uri determination: {}", e.getMessage());
		}
	}

	@Nonnull
	private String getOrDefaultKeyId(Token token) {
		if (configuration.isLegacyMode()) {
			return KEY_ID_VALUE_LEGACY;
		}
		if (token.hasHeaderParameter(KEY_ID_PARAMETER_NAME)) {
			return token.getHeaderParameterAsString(KEY_ID_PARAMETER_NAME);
		}
		return DEFAULT_KEY_ID; // TODO IAS default key-id can be removed when IAS provides key id
	}

	@Nonnull
	private String getOrDefaultSignatureAlgorithm(Token token) {
		String algHeader = token.getHeaderParameterAsString(ALGORITHM_PARAMETER_NAME);

		if (token.hasHeaderParameter(ALGORITHM_PARAMETER_NAME)
				&& JwtSignatureAlgorithm.fromValue(algHeader) == null) { // check whether alg is supported
			throw new IllegalArgumentException(
					"Jwt token with signature algorithm '" + algHeader + "' is not supported.");
		}
		return JwtSignatureAlgorithm.RS256.value();
	}

	@Nonnull
	private String getOrRequestJwksUri(Token token) throws OAuth2ServiceException {
		if (configuration.isLegacyMode()) {
			// hard-code with trusted url in case of XSA Auth Code tokens
			return configuration.getUrl() + "/token_keys";
		}
		if (configuration.getService() == Service.XSUAA && token.hasHeaderParameter(KEYS_URL_PARAMETER_NAME)) {
			// 'jku' was validated by XsuaaJkuValidator
			return token.getHeaderParameterAsString(KEYS_URL_PARAMETER_NAME);
		}
		if (configuration.getService() != Service.XSUAA && token.getIssuer() != null) {
			// 'iss' claim was validated by JwtIssuerValidator
			// don't call in case of XSA Auth Code tokens as issuer is not valid there
			// as XSUAA issuer contains often localhost this was not validated as well
			URI discoveryUri = DefaultOidcConfigurationService.getDiscoveryEndpointUri(token.getIssuer());
			URI jkuUri = oidcConfigurationService
					.getOrRetrieveEndpoints(discoveryUri)
					.getJwksUri();
			if (jkuUri != null) {
				return jkuUri.toString();
			}
		}
		throw new IllegalArgumentException(
				"Token signature can not be validated as jwks uri can not be determined: Token does not provide the required 'jku' header or issuer claim.");
	}

	// for testing
	ValidationResult validate(String token, String tokenAlgorithm, String tokenKeyId, String tokenKeysUrl,
			@Nullable String fallbackPublicKey, @Nullable String appTid, @Nullable String azp) {
		assertHasText(token, "token must not be null or empty.");
		assertHasText(tokenAlgorithm, "tokenAlgorithm must not be null or empty.");
		assertHasText(tokenKeyId, "tokenKeyId must not be null or empty.");
		assertHasText(tokenKeysUrl, "tokenKeysUrl must not be null or empty.");

		return Validation.getInstance().validate(tokenKeyService, token, tokenAlgorithm, tokenKeyId,
				URI.create(tokenKeysUrl), fallbackPublicKey, appTid, configuration.getClientId(), azp);
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

		ValidationResult validate(OAuth2TokenKeyServiceWithCache tokenKeyService, String token,
								  String tokenAlgorithm, String tokenKeyId, URI tokenKeysUrl, @Nullable String fallbackPublicKey,
								  @Nullable String appTid, String clientId, String azp) {
			ValidationResult validationResult;

			validationResult = setSupportedJwtAlgorithm(tokenAlgorithm);
			if (validationResult.isErroneous()) {
				return validationResult;
			}
			validationResult = setPublicKey(tokenKeyService, tokenKeyId, tokenKeysUrl, appTid, clientId, azp);
			if (validationResult.isErroneous()) {
				if (fallbackPublicKey != null) {
					try {
						this.publicKey = JsonWebKeyImpl.createPublicKeyFromPemEncodedPublicKey(
								JwtSignatureAlgorithm.RS256, fallbackPublicKey);

					} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
						return createInvalid(
								"Error occurred during signature validation: ({}). Fallback with configured 'verificationkey' was not successful.",
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

		private ValidationResult setSupportedJwtAlgorithm(String tokenAlgorithm) {
			if (tokenAlgorithm != null) {
				jwtSignatureAlgorithm = JwtSignatureAlgorithm.fromValue(tokenAlgorithm);
				if (jwtSignatureAlgorithm != null) {
					return createValid();
				}
				return createInvalid("Jwt token with signature algorithm '{}' is not supported.", tokenAlgorithm);
			}
			return createValid();
		}

		private ValidationResult setPublicKey(OAuth2TokenKeyServiceWithCache tokenKeyService, String keyId,
											  URI keyUri, String zoneId, String clientId, String azp) {
			try {
				this.publicKey = tokenKeyService.getPublicKey(jwtSignatureAlgorithm, keyId, keyUri, zoneId, clientId, azp);
			} catch (OAuth2ServiceException e) {
				return createInvalid("Error retrieving Json Web Keys from Identity Service: {}.", e.getMessage());
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				return createInvalid("Error creating PublicKey from Json Web Key received from {}: {}.",
						keyUri, e.getMessage());
			}
			if (this.publicKey == null) {
				return createInvalid(
						"There is no Json Web Token Key with keyId '{}' and type '{}' found on jwks uri {} for zone '{}' to prove the identity of the Jwt.",
						keyId, jwtSignatureAlgorithm.type(), keyUri, zoneId);
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
			String headerAndPayload = tokenHeaderPayloadSignature[0] + "." +
					tokenHeaderPayloadSignature[1];
			try {
				publicSignature.initVerify(publicKey);
				publicSignature.update(headerAndPayload.getBytes(UTF_8)); // provide data

				byte[] decodedSignatureBytes = Base64.getUrlDecoder().decode(tokenHeaderPayloadSignature[2]);

				if (publicSignature.verify(decodedSignatureBytes)) {
					return createValid();
				}
				return createInvalid(
						"Signature of Jwt Token is not valid: the identity provided by the JSON Web Token Key can not be verified (Signature: {}).",
						tokenHeaderPayloadSignature[2]);
			} catch (Exception e) {
				return createInvalid("Error occurred during Json Web Signature Validation: {}.", e.getMessage());
			}
		}
	}

}
