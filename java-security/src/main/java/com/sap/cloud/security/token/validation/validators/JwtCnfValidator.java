package com.sap.cloud.security.token.validation.validators;

import com.sap.cloud.security.json.JsonObject;
import com.sap.cloud.security.token.SecurityContext;
import com.sap.cloud.security.token.Token;
import com.sap.cloud.security.token.TokenClaims;
import com.sap.cloud.security.token.validation.ValidationResult;
import com.sap.cloud.security.token.validation.ValidationResults;
import com.sap.cloud.security.token.validation.Validator;
import com.sap.cloud.security.xsuaa.mtls.X509Parser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Validates if the jwt access token is intended for the OAuth2 client of this
 * application, in certificate based authentication scenario. The cnf claim
 * provides the SHA-256 thumbprint of the X.509 certificate information, this
 * information needs to match the thumbprint of the provided certificate.
 * <p>
 * Validates whether there 'cnf' thumbprint value matches with the X509
 * certificate from the request.
 */
public class JwtCnfValidator implements Validator<Token> {
	private static final Logger LOGGER = LoggerFactory.getLogger(JwtCnfValidator.class);
	private final String trustedClientId;
	// TODO python script enhancement

	public JwtCnfValidator(String clientId) {
		trustedClientId = clientId;
	}

	/**
	 * Validates the cnf thumbprint of X509 certificate against trusted certificate thumbprint.
	 * @param token token to be validated
	 * @return validation result. Result is valid when thumbprints match.
	 */
	@Override
	public ValidationResult validate(Token token) {

		String cnf = extractCnfThumbprintFromToken(token);
		if (cnf == null && token.getAudiences().size() == 1 && token.getAudiences().contains(trustedClientId)){
			return ValidationResults.createValid();
		} else {
			String trustedCertificate = SecurityContext.getCertificate();
			LOGGER.info("Cnf thumbprint: {}", cnf);
			try {
				String trustedX509Thumbprint = X509Parser.getX509Thumbprint(trustedCertificate);
				if (trustedX509Thumbprint.equals(cnf)) {
					return ValidationResults.createValid();
				}
			} catch (NoSuchAlgorithmException e) {
				LOGGER.error("Couldn't generate the x509 thumbprint. {}", e.getMessage(), e);
			} catch (CertificateException e) {
				LOGGER.error("Couldn't generate thumbprint of X509 certificate", e);
			}
			return ValidationResults.createInvalid("Invalid x509 thumbprint.");
		}
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
		return cnf == null ? null : cnf.getAsString(TokenClaims.X509_THUMBPRINT);
	}

}
