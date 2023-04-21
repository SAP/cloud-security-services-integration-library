/**
 * SPDX-FileCopyrightText: 2018-2023 SAP SE or an SAP affiliate company and Cloud Security Client Java contributors
 * <p>
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.config.OAuth2ServiceConfiguration;
import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.x509.Certificate;
import com.sap.cloud.security.xsuaa.Assertions;

import javax.annotation.Nullable;

/**
 * Validates if the jwt access token is intended for the OAuth2 client of this
 * application, in certificate based authentication scenario. The cnf claim
 * provides the SHA-256 thumbprint of the X.509 certificate information, this
 * information needs to match the thumbprint of the provided certificate.
 * <p>
 * Validates whether there 'cnf' thumbprint value matches with the X509
 * certificate from the request.
 * <p>
 * Validator is by default disabled. It can be activated by setting environment
 * variable 'X5T_VALIDATOR_ENABLED' to true.
 */
public class JwtX5tValidator implements Validator<Token> {

	public JwtX5tValidator(OAuth2ServiceConfiguration config) {
		Assertions.assertNotNull(config, "Service configuration must not be null");
	}

	/**
	 * Validates the cnf thumbprint of X509 certificate against trusted
	 * certificate's thumbprint.
	 * <p>
	 * In case audience contains only a single value, thumbprint comparison is not
	 * performed and request is validated. To guarantee that this single audience is
	 * trusted, use this validator in combination with {@link JwtAudienceValidator}
	 *
	 * @param token
	 *            token to be validated
	 * @return validation result. Result is valid when both thumbprints match in
	 *         case of multiple audiences.
	 */
	@Override
	public ValidationResult validate(Token token) {
		if (token == null) {
			return ValidationResults.createInvalid("No token passed to validate certificate thumbprint");
		}
		String tokenX5t = extractCnfThumbprintFromToken(token);
		if (tokenX5t == null) {
			return ValidationResults.createInvalid("Token doesn't contain certificate thumbprint confirmation method");
		}
		Certificate clientCertificate = SecurityContext.getClientCertificate();
		if (clientCertificate == null) {
			return ValidationResults.createInvalid("Client certificate missing from SecurityContext");
		}
		String clientCertificateX5t = clientCertificate.getThumbprint();
		if (clientCertificateX5t.equals(tokenX5t)) {
			return ValidationResults.createValid();
		}
		return ValidationResults.createInvalid(
				"Certificate thumbprint validation failed with Token 'cnf' thumbprint: {} != {}", tokenX5t,
				clientCertificateX5t);
	}

	/**
	 * Extract cnf attribute value of 'x5t#S256' (SHA-256 hashed certificate
	 * thumbprint) from token.
	 *
	 * @param token
	 *            received token
	 * @return cnf value of 'x5t#S256' or null if value is not present
	 */
	@Nullable
	private static String extractCnfThumbprintFromToken(Token token) {
		JsonObject cnf = token.getClaimAsJsonObject(TokenClaims.CNF);
		return cnf == null ? null : cnf.getAsString(TokenClaims.CNF_X5T);
	}

}
