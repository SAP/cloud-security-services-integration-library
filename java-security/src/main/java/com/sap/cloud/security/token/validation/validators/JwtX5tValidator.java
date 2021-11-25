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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

/**
 * Validates if the jwt access token is intended for the OAuth2 client of this
 * application, in certificate based authentication scenario. The cnf claim
 * provides the SHA-256 thumbprint of the X.509 certificate information, this
 * information needs to match the thumbprint of the provided certificate.
 * <p>
 * Validates whether there 'cnf' thumbprint value matches with the X509
 * certificate from the request.
 *
 * Validator is by default disabled. It can be activated by setting environment
 * variable 'X5T_VALIDATOR_ENABLED' to true.
 */
public class JwtX5tValidator implements Validator<Token> {

	private static final Logger LOGGER = LoggerFactory.getLogger(JwtX5tValidator.class);
	private final OAuth2ServiceConfiguration config;


	public JwtX5tValidator(OAuth2ServiceConfiguration config) {
		this.config = config;
	}

	/**
	 * Validates the cnf thumbprint of X509 certificate against trusted
	 * certificate's thumbprint.
	 *
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
		String tokenX5t = extractCnfThumbprintFromToken(token);
		LOGGER.debug("Token 'cnf' thumbprint: {}", tokenX5t);
		if (tokenX5t != null) {
			Certificate clientCertificate = SecurityContext.getClientCertificate();
			if (clientCertificate == null) {
				LOGGER.error("Client certificate missing from SecurityContext");
				return ValidationResults.createInvalid("Certificate validation failed");
			}
			String clientCertificateX5t = clientCertificate.getThumbprint();
			if (clientCertificateX5t.equals(tokenX5t)) {
				if (token.getAudiences().size() == 1 && token.getAudiences().contains(config.getClientId())) {
					return ValidationResults.createValid();
				}
				LOGGER.error("Audience validation failed -> \"aud\": {} != \"clientid\": \"{}\"", token.getAudiences(), config.getClientId());
			} else {
				LOGGER.error("Thumbprint validation failed -> x5t from token: \"{}\" != thumbprint from client certificate: \"{}\"", tokenX5t,
						clientCertificateX5t);
			}
		}
		return ValidationResults.createInvalid("Certificate validation failed");
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
